# RouterOS PCC and Flapping Management Script (Overseer)

## Overview
**Overseer** is a Mikrotik RouterOS script designed to monitor blackhole routes (distance 100, non-main routing-table) for flapping events. It employs a cooldown mechanism to avoid counting rapid repeated flaps, escalating the disable duration of PCC (per-connection-classifier) rules when necessary and reducing it when routes stabilize.

## Features
- **Flap Monitoring**: Continuously watches for route state changes indicating flaps.
- **Cooldown Mechanism**: Ensures a flap is only counted after a 5-minute cooldown period.
- **Escalating Disable Duration**: PCC rules are disabled for progressively longer durations as flaps accumulate.
- **Permanent Disable**: Routes reaching a disable period beyond 24 hours are permanently disabled.
- **Stabilization Reward**: Gradually reduces disable duration when a route remains stable.
- **PCC Auto-Sort**: Automatically redistributes PCC values for balanced connection tracking.
- **Comprehensive Logging**: Debug, info, warning, and error logs aid in monitoring and troubleshooting.

## Requirements
- **Mikrotik RouterOS**: Tested on recent RouterOS versions.
- **Configured PCC Rules**: Ensure firewall mangle PCC rules have appropriate comments (must include "pcc") for matching.

## Installation
1. **Upload the Script**  
   Copy the `overseer.rsc` to your RouterOS device.

2. **Import the Script**  
   Use the command below in your RouterOS terminal:
   ```
   /import file=overseer.rsc
   ```

3. **Schedule Execution**  
   To ensure continuous monitoring, schedule the script to run periodically using scheduler.

## Configuration
The script uses several global variables that are automatically initialized:
- `blackholeRouteStateMap`
- `flapCounts`
- `disableUntil`
- `disablePermanently`
- `stableSince`
- `rewardMultiplier`
- `lastFlapTime`

Internal parameters you can adjust include:
- `flapThresholdCount` (default 3)
- `cooldown` period (default 300 seconds)
- `disableDuration` (default 3600 seconds)
- `permanentDisableThreshold` (default 86400 seconds)
- `stableTimeThreshold` (default 3600 seconds)

Feel free to modify these values directly in the script to best suit your network environment.

## How It Works
1. **Route Monitoring**: Iterates through blackhole routes using the command:
   ```
   /ip route find distance=100 routing-table!=main
   ```
   This finds routes marked with a distance of 100 and that do not belong to the main routing table – typically indicating blackhole routes.
2. **Flap Detection**: A transition from inactive to active is treated as a flap, counted only if a configurable cooldown period has passed.
3. **Disabling PCC**: When flaps exceed the threshold, PCC rules are disabled for a duration that escalates with repeated flaps.
4. **Stabilization & Recovery**: Once a route remains stable, the disable period is reduced gradually, restoring normal operation.
5. **PCC Auto-Sort**: After changes are applied, the script calls a function (`pccAutoSort`) to rebalance the per-connection-classifier values for firewall mangle rules. It does this by matching the route’s comment (which carries persistent data in a "pccData:" prefix) with firewall mangle rules whose comments include the string "pcc". This ensures that PCC rules consistently align with the current state of the monitored routes.

## Blackhole Routes & PCC Matching
The script locates blackhole routes by:
- Using `/ip route find` with criteria `distance=100` and `routing-table!=main` to extract potential blackhole routes.
- For each route, it reads the comment field. If the comment starts with "pccData:", it extracts persistent parameters.
- The script then matches these routes with firewall mangle rules by searching for mangle rules that have a comment containing "pcc" and a connection mark that corresponds to the processed route.
- This linkage allows the script to directly disable or re-enable PCC rules based on real-time route state changes.

### RoutingTableForMatch Explanation
In the script, a local variable `routingTableForMatch` is used to normalize the routing table name for matching purposes.  
- If the routing table name ends with a trailing "-L" (indicating, for example, a load-balanced variant), the script removes the last character to produce a base name.  
- This normalized name is then used in comparisons against connection marks in firewall mangle rules, ensuring that matching is consistent even if the routing table name has extra suffixes.

## License
This script is offered "as-is", without any express or implied warranty. You are free to use, modify, and distribute it.

## Production and AI Assistance
This script is currently used in production environments and has been developed with AI assistance to ensure reliability and ease of customization. Contributions and modifications are welcomed to further improve its robustness.