<div align=center>
<img src="./icon.webp" width=130>
<h1>Goodnight · 晚安好梦</h1>
<h3>Fixes S0 StandBy</h3>
<img src="./screenshot.webp" />
</div>

### What would the project do?
**In a nutshell** - Improve your laptop's standby experience & Eliminate concerns about battery drain while in your bag.

**In detail**
 - Suspend nearly all processes during sleep.
 - Disable network connections, mouse input, and keyboard input while sleeping.
 - Quickly return to sleep if accidentally awakened.
 - Log kernel power events.
 - Turn off "Away Mode" to prevent interference with normal S0 sleep.

Goodnight is a CLI application, a GUI application, and a C++ library that provides a clear interface over Windows power events and management.

### Usage

#### GUI
Open the GUI and enable the functions you needs.

#### CLI
```text

     ___                _     __ _       _     _
    / _ \___   ___   __| | /\ \ (_) __ _| |__ | |_
   / /_\/ _ \ / _ \ / _` |/  \/ / |/ _` | '_ \| __|
  / /_\\ (_) | (_) | (_| / /\  /| | (_| | | | | |_
  \____/\___/ \___/ \__,_\_\ \/ |_|\__, |_| |_|\__|
                                   |___/

    Goodnight CLI v0.1.1

USAGE:
  goodnight-cli.exe [-k|--keep-sleep] [-l|--wake-log] [-s|--suspend-processes] [-w|-a|--wakeup-actions <wakeupActions>] [-v|--verbose] [-d|--disable-devices] [-?|-h|--help]

Display usage information.

OPTIONS, ARGUMENTS:
  -k, --keep-sleep        Keep the system in sleep mode
  -l, --wake-log          Log the wake events
  -s, --suspend-processes Suspend processes on sleep
  -w, -a, --wakeup-actions <wakeupActions>
                          Wakeup actions [DisplayOn, PowerButton, Keyboard, Mouse, TouchPad, ACDCPower, Other, All]
  -v, --verbose           Verbose log
  -d, --disable-devices   Disable devices on sleep
  -?, -h, --help
```

<sup><sub>Fuck Microsoft. Fuck AMD & Intel.</sub></sup>
