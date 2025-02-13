# =====================================================================
# Overseer
# Mikrotik RouterOS PCC and Flapping Management Script v2.1
#
# This script monitors blackhole routes (distance=100, non-main routing-table)
# for flapping events using a cooldown mechanism to avoid rapid repeated counts.
# If a route flaps (inactive -> active) too many times, PCC rules (per-connection-classifier)
# are disabled for escalating durations.
# When a blackhole route remains stable (inactive) continuously, the disable duration is reduced
# exponentially. Global variables track route state, flap counts, disable durations,
# permanent disable flags, and reward multipliers.
# Logging (debug, info, warning, error) is used throughout the script.
# =====================================================================

# Global Variable Initialization
:global blackholeRouteStateMap
:if ([:typeof $blackholeRouteStateMap] = "nothing") do={
    :set blackholeRouteStateMap [:toarray ""]
    :log debug message=("Initialized blackholeRouteStateMap array")
}
:global flapCounts
:if ([:typeof $flapCounts] = "nothing") do={
    :set flapCounts [:toarray ""]
    :log debug message=("Initialized flapCounts array")
}
:global disableUntil
:if ([:typeof $disableUntil] = "nothing") do={
    :set disableUntil [:toarray ""]
    :log debug message=("Initialized disableUntil array")
}
:global disablePermanently
:if ([:typeof $disablePermanently] = "nothing") do={
    :set disablePermanently [:toarray ""]
    :log debug message=("Initialized disablePermanently array")
}
:global stableSince
:if ([:typeof $stableSince] = "nothing") do={
    :set stableSince [:toarray ""]
    :log debug message=("Initialized stableSince array")
}
:global rewardMultiplier
:if ([:typeof $rewardMultiplier] = "nothing") do={
    :set rewardMultiplier [:toarray ""]
    :log debug message=("Initialized rewardMultiplier array")
}
:global flapResetDate
:local currentDate [/system clock get date]
:if ($flapResetDate != $currentDate) do={
    :set flapResetDate $currentDate
    :set flapCounts [:toarray ""]
    :log debug message=("Flap counts reset for new day: " . $currentDate)
}
:global lastFlapTime
:if ([:typeof $lastFlapTime] = "nothing") do={
    :set lastFlapTime [:toarray ""]
    :log debug message=("Initialized lastFlapTime array")
}

:local flapThresholdCount 3

:local uniqueComments
:local changesMade false

:local now [:totime ([/system clock get date] . " " . [/system clock get time])]

# Function: pccAutoSort
# Adjusts the per-connection-classifier values for rules matching a specific comment.
# This ensures PCC rules are balanced after any changes.
:local pccAutoSort do={
    :log debug message=("Running pccAutoSort for comment: " . $1)
    :local rulesWithComment [/ip firewall mangle find where comment=$1 disabled=no action=mark-connection]
    :local denominator [:len $rulesWithComment]
    :local remainder 0
    :foreach ruleId in=$rulesWithComment do={
        :local currentClassifier [/ip firewall mangle get $ruleId per-connection-classifier]
        :local classifierType [:pick $currentClassifier 0 [:find $currentClassifier ":"]]
        :local newClassifier ($classifierType . ":$denominator/$remainder")
        /ip firewall mangle set $ruleId per-connection-classifier=$newClassifier
        :log debug message=("Set new PCC value: " . $newClassifier . " for rule " . $ruleId)
        :set remainder ($remainder + 1)
    }
}

# Unique Comments Initialization
# Collect unique comments from PCC rules for later processing.
:foreach rule in=[/ip firewall mangle find where action=mark-connection] do={
    :local currentComment [/ip firewall mangle get $rule comment]
    :if ($currentComment~"pcc") do={
        :local found false
        :foreach existingComment in=$uniqueComments do={
            :if ($currentComment=$existingComment) do={
                :set found true
            }
        }
        :if ($found=false) do={
            :set uniqueComments ($uniqueComments, $currentComment)
            :log debug message=("Added unique comment: " . $currentComment)
        }
    }
}

# Main Route Processing Loop
# Process routes with distance=100 and non-main routing-table.
:foreach i in=[/ip route find distance=100 routing-table!=main] do={
    # Initialize route variables.
    :local routingTable [:tostr [/ip route get $i routing-table]]
    :local routeComment [:tostr [/ip route get $i comment]]
    :local isActive false
    :local flapCount 0
    :local previousState false
    :local routingTableForMatch ""
    :local persistentData [:toarray ""]
    :local cooldown 300
    :local disableDuration 3600
    :local permanentDisableThreshold 86400
    :local stableTimeThreshold 3600

    # Check if route is active.
    :if ([/ip route get $i active]=true) do={
        :set isActive true
    }
    :log debug message=("Processing route: " . $routingTable . " with active state: " . $isActive)

    # Set routingTableForMatch without trailing "-L" if present.
    :if ($routingTable ~ ".*-L") do={
        :set routingTableForMatch [:pick $routingTable 0 ([:len $routingTable] - 1)]
    }

    # Initialize route state if not present.
    :if ([:typeof ($blackholeRouteStateMap->$routingTable)]="nothing") do={
        :set ($blackholeRouteStateMap->$routingTable) $isActive
        :log debug message=("Added state for route " . $routingTable . " with active=" . $isActive)
        :set previousState ($blackholeRouteStateMap->$routingTable)
        :log debug message=("Retrieved state for route " . $routingTable . " with active=" . $isActive)
    } else={
        :set previousState ($blackholeRouteStateMap->$routingTable)
        :log debug message=("Retrieved state for route " . $routingTable . " with active=" . $isActive)
    }

    # Initialize flap count for route if not present.
    :if ([:typeof ($flapCounts->$routingTable)]!="nothing") do={
        :set flapCount ($flapCounts->$routingTable)
    }

    # Extract persistent data (format: "pccData:perm=<true|false>;mult=<N>;stable=<timestamp>;rs=<true|false>")
    :if ($routeComment~"pccData:") do={
        :local dataParts [:toarray [:pick $routeComment 8 [:len $routeComment]]]
        :foreach part in=$dataParts do={
            :local key [:pick $part 0 [:find $part "="]]
            :local value [:pick $part ([:find $part "="] + 1) [:len $part]]
            :set ($persistentData->$key) $value
        }
    }
    # Use persistentData to override in‑memory variables only if not already set:
    :if (([:typeof ($disablePermanently->$routingTable)]="nothing") && ([:typeof ($persistentData->"perm")]!="nothing")) do={        
        :set ($disablePermanently->$routingTable) ($persistentData->"perm")
    }
    :if (([:typeof ($rewardMultiplier->$routingTable)]="nothing") && ([:typeof ($persistentData->"mult")]!="nothing")) do={
        :set ($rewardMultiplier->$routingTable) ($persistentData->"mult")
    }
    :if (([:typeof ($stableSince->$routingTable)]="nothing") && ([:typeof ($persistentData->"stable")]!="nothing")) do={
        :set ($stableSince->$routingTable) ($persistentData->"stable")
    }
    :if (([:typeof ($blackholeRouteStateMap->$routingTable)]="nothing") && ([:typeof ($persistentData->"rs")]!="nothing")) do={
        :set ($blackholeRouteStateMap->$routingTable) ($persistentData->"rs")
    }

    # Evaluate route flapping and disable PCC rules if necessary.
    :if (($previousState=false) && ($isActive)) do={
        :if ([:typeof ($disablePermanently->$routingTable)]="nothing" || ($disablePermanently->$routingTable=false)) do={
            :if ([:typeof ($disableUntil->$routingTable)]="nothing" || ($now >= ($disableUntil->$routingTable))) do={
                :foreach uniqueComment in=$uniqueComments do={
                    :foreach x in=[/ip firewall mangle find comment=$uniqueComment new-connection-mark~$routingTableForMatch disabled=no] do={
                        /ip firewall mangle set $x disabled=yes
                    }
                }
                :set changesMade true
                :set ($blackholeRouteStateMap->$routingTable) $isActive                
            }
        }
        :set ($stableSince->$routingTable)
        :if ([:typeof ($disablePermanently->$routingTable)]="nothing" || ($disablePermanently->$routingTable=false)) do={
            # Evaluate flap count and reset last flap time.
            :if (([:typeof ($lastFlapTime->$routingTable)] = "nothing") || (($now - ($lastFlapTime->$routingTable)) >= [:totime $cooldown])) do={
                :if ([:typeof ($flapCounts->$routingTable)]="nothing") do={
                    :set ($flapCounts->$routingTable) 1
                } else={
                    :set ($flapCounts->$routingTable) (($flapCounts->$routingTable) + 1)
                }
                :set ($lastFlapTime->$routingTable) $now
                :log info message=("Flap detected for ".$routingTable.". New flap count: ". ($flapCounts->$routingTable))
            }
            # Check if flap count exceeds threshold to disable PCC rules.
            :if (($flapCounts->$routingTable) >= $flapThresholdCount) do={
                # Disable PCC rules for the route and mark disable until time
                :if ([:typeof ($disableUntil->$routingTable)]="nothing") do={
                    :set ($disableUntil->$routingTable) ($now + [:totime $disableDuration])
                } else={
                    :if ($now < ($disableUntil->$routingTable)) do={
                        :set ($disableUntil->$routingTable) (($disableUntil->$routingTable) + [:totime $disableDuration])
                    } else={
                        :set ($disableUntil->$routingTable) ($now + [:totime $disableDuration])
                    }
                }
                # Check if permanent disable threshold is reached.
                :if ((($disableUntil->$routingTable) - $now) >= [:totime $permanentDisableThreshold]) do={
                    :set ($disablePermanently->$routingTable) true
                    :log warning message=("Permanent disable triggered for route $routingTable")
                } else={
                    :log info message=("Disabling PCC for route ".$routingTable. " due to flapping. Disable until: ".($disableUntil->$routingTable))
                }
                :set ($flapCounts->$routingTable) 0
            }
        }
    }
    # Evaluate route stabilization and re-enable PCC rules.
    :if (($previousState=true) && ($isActive=false)) do={
        :if ([:typeof ($disablePermanently->$routingTable)]="nothing" || (($disablePermanently->$routingTable)=false)) do={
            :if ([:typeof ($disableUntil->$routingTable)]="nothing" || ($now >= ($disableUntil->$routingTable))) do={
                :foreach uniqueComment in=$uniqueComments do={
                    :foreach x in=[/ip firewall mangle find comment=$uniqueComment new-connection-mark~$routingTableForMatch disabled=yes] do={
                        /ip firewall mangle set $x disabled=no
                    }
                }
                :if ([:typeof ($disableUntil->$routingTable)]!="nothing") do={
                    :set ($disableUntil->$routingTable)
                }
                :set changesMade true
                :set ($blackholeRouteStateMap->$routingTable) $isActive
            }
        }
        :set ($stableSince->$routingTable) $now
        # Reset reward multiplier for the route.
        :set ($rewardMultiplier->$routingTable) 1
        :set changesMade true
    }    
    # Check for stabilized routes to reduce disable duration with exponential reward.
    :if (($previousState=false) && ($isActive=false) && ([:typeof ($stableSince->$routingTable)]!="nothing")) do={
        :local stableTime ($now - ($stableSince->$routingTable))
        :if ($stableTime >= [:totime $stableTimeThreshold]) do={
            # Initialize reward multiplier for the route if not set.
            :if ([:typeof ($rewardMultiplier->$routingTable)] = "nothing") do={
                :set ($rewardMultiplier->$routingTable) 1
            }
            :local multiplier ($rewardMultiplier->$routingTable)
            :local reduction ([:totime ($stableTimeThreshold * $multiplier)])
            :local currentDisable ($disableUntil->$routingTable)
            :if ($currentDisable > $now) do={
                :local newDisable ($currentDisable - $reduction)
                :if ($newDisable < $now) do={
                    :set newDisable $now
                }
                :set ($disableUntil->$routingTable) $newDisable
                :log info message=("Route stabilized over time: reduced disable duration for ".$routingTable." by ".$reduction." to ".$newDisable)
                # Update stableSince to avoid repeated reward within the same period.
                :set ($stableSince->$routingTable) $now
                # Increase reward multiplier for the route.
                :set ($rewardMultiplier->$routingTable) ($multiplier * 2)
            }
        }
    }

    # Update route comment with persistent data if changed.
    :local newData ""
    :if ([:typeof ($disablePermanently->$routingTable)]!="nothing") do={
        :set newData ("perm=" . ($disablePermanently->$routingTable))
    }
    :if ([:typeof ($rewardMultiplier->$routingTable)]!="nothing") do={
        :if ([:len $newData] > 0) do={
            :set newData ($newData . ";mult=" . ($rewardMultiplier->$routingTable))
        } else={
            :set newData ("mult=" . ($rewardMultiplier->$routingTable))
        }
    }
    :if ([:typeof ($stableSince->$routingTable)]!="nothing") do={
        :if ([:len $newData] > 0) do={
            :set newData ($newData . ";stable=" . ($stableSince->$routingTable))
        } else={
            :set newData ("stable=" . ($stableSince->$routingTable))
        }
    }
    :if ([:typeof ($blackholeRouteStateMap->$routingTable)]!="nothing") do={
        :if ([:len $newData] > 0) do={
            :set newData ($newData . ";rs=" . ($blackholeRouteStateMap->$routingTable))
        } else={
            :set newData ("rs=" . ($blackholeRouteStateMap->$routingTable))
        }
    }
    :local newComment ("pccData:" . $newData)
    :if (([:len $newData] > 0) && ($newComment != $routeComment)) do={
        /ip route set $i comment=$newComment
    }
}
# Run PCC Auto-Sort if needed
:if ($changesMade) do={
    :log debug message="Running PCC Auto-Sort due to detected changes."
    :foreach uniqueComment in=$uniqueComments do={
        $pccAutoSort $uniqueComment
    }
}
# End of script execution logging.
:log debug message="Completed RouterOS PCC flapping script execution."
