## Alarm Server
## Supporting Envisalink 2DS/3
## Written by donnyk+envisalink@gmail.com
##
## This code is under the terms of the GPL v3 license.


evl_Defaults = {
	'zone' : {'open' : False, 'fault' : False, 'alarm' : False, 'tamper' : False},
	'partition' : {'ready' : False, 'trouble' : False, 'exit_delay' : False, 'entry_delay' : False, 'armed' : False, 'armed_bypass' : False, 'alarm' : False, 'tamper' : False, 'chime' : False, 'trouble_led' : False},
	'system' : {'fire_key_alarm' : False, 'aux_key_alarm' : False, 'panic_key_alarm' : False, '2wire_alarm' : False, 'battery_trouble' : False, 'ac_trouble' : False, 'system_bell_trouble' : False, 'system_tamper' : False, 'fire_trouble' : False}
	}

evl_ArmModes = {
        0 : 'Away',
        1 : 'Stay',
        2 : 'Zero Entry Away',
        3 : 'Zero Entry Stay'
    }

evl_Partition_Status_Codes = {
    '00' : 'Partition is not used or doesn''t exist',
    '01' : 'Ready',
    '02' : 'Ready to Arm (Zones are Bypasses)',
    '03' : 'Not Ready',
    '04' : 'Armed in Stay Mode',
    '05' : 'Armed in Away Mode',
    '06' : 'Armed Maximum (Zero Entry Delay)',
    '07' : 'Exit Delay',
    '08' : 'Partition is in Alarm',
    '09' : 'Alarm Has Occurred (Alarm in Memory'
}

evl_Virtual_Keypad_How_To_Beep = {
    '00' : 'off',
    '01' : 'beep 1 time',
    '02' : 'beep 2 times',
    '03' : 'beep 3 times',
    '04' : 'continous fast beep',
    '05' : 'continuous slow beep'
}

evl_CID_Qualifiers = {
    1 : 'New Event or Opening',
    3 : 'New Restore or Closing',  
    6 : 'Previously Reported Condition Still Present'
}

evl_CID_Events = {
    100 : {
    "label" : "Medical Alert",
    "type"  : "zone",
    },
    101 : {
    "label" : "Personal Emergency",
    "type"  : "zone",
    },
    102 : {
    "label" : "Failure to Report In",
    "type"  : "zone",
    },
    110 : {
    "label" : "Fire Alarm",
    "type"  : "zone",
    },
    111 : {
    "label" : "Smoke Alarm",
    "type"  : "zone",
    },
    112 : {
    "label" : "Combustion Detected Alarm",
    "type"  : "zone",
    },
    113 : {
    "label" : "Water Flood Alarm",
    "type"  : "zone",
    },
    114 : {
    "label" : "Excessive Heat Alarm",
    "type"  : "zone",
    },
    115 : {
    "label" : "Fire Alarm Pulled",
    "type"  : "zone",
    },
    116 : {
    "label" : "Duct Alarm",
    "type"  : "zone",
    },
    117 : {
    "label" : "Flame Detected",
    "type"  : "zone",
    },
    118 : {
    "label" : "Near Alarm",
    "type"  : "zone",
    },
    120 : {
    "label" : "Panic Alarm",
    "type"  : "zone",
    },
    121 : {
    "label" : "Duress Alarm",
    "type"  : "user",
    },
    122 : {
    "label" : "Alarm, 24-hour Silent",
    "type"  : "zone",
    },
    123 : {
    "label" : "Alarm, 24-hour Audible",
    "type"  : "zone",
    },       
    124 : {
    "label" : "Duress - Access granted",
    "type"  : "zone",
    },
    125 : {
    "label" : "Duress - Egress granted",
    "type"  : "zone",
    },
    130 : {
    "label" : "Burgalry in Progress",
    "type"  : "zone",
    },
    131 : {
    "label" : "Alarm, Perimeter",
    "type"  : "zone",
    },
    132 : {
    "label" : "Alarm, Interior",
    "type"  : "zone",
    },
    133 : {
    "label" : "24 Hour (Safe)",
    "type"  : "zone",
    },
    134 : {
    "label" : "Alarm, Entry/Exit",
    "type"  : "zone",
    },
    135 : {
    "label" : "Alarm, Day/Night",
    "type"  : "zone",
    },
    136 : {
    "label" : "Alarm, Outdoor",
    "type"  : "zone",
    },
    137 : {
    "label" : "Alarm, Tamper",
    "type"  : "zone",
    },
    138 : {
    "label" : "Near Alarm",
    "type"  : "zone",
    },
    139 : {
    "label" : "Intrusion Verifier",
    "type"  : "zone",
    },
    140 : {
    "label" : "Alarm, General Alarm",
    "type"  : "zone",
    },
    141 : {
    "label" : "Alarm, Polling Loop Open",
    "type"  : "zone",
    },
    142 : {
    "label" : "Alarm, Polling Loop Short",
    "type"  : "zone",
    },
    143 : {
    "label" : "Alarm, Expansion Module",
    "type"  : "zone",
    },
    144 : {
    "label" : "Alarm, Sensor Tamper",
    "type"  : "zone",
    },
    145 : {
    "label" : "Alarm, Expansion Module Tamper",
    "type"  : "zone",
    },
    146 : {
    "label" : "Silent Burglary",
    "type"  : "zone",
    },
    147 : {
    "label" : "Sensor Supervision failure",
    "type"  : "zone",
    },
    150 : {
    "label" : "Alarm, 24-Hour Auxiliary",
    "type"  : "zone",
    },
    151 : {
    "label" : "Alarm, Gas detected",
    "type"  : "zone",
    },
    152 : {
    "label" : "Alarm, Refrigeration",
    "type"  : "zone",
    },
    153 : {
    "label" : "Alarm, Loss of heat",
    "type"  : "zone",
    },
    154 : {
    "label" : "Alarm, Water leakage",
    "type"  : "zone",
    },
    155 : {
    "label" : "Alarm, foil break",
    "type"  : "zone",
    },
    156 : {
    "label" : "Day trouble",
    "type"  : "zone",
    },
    157 : {
    "label" : "Low bottled gas level",
    "type"  : "zone",
    },
    158 : {
    "label" : "Alarm, High temperature",
    "type"  : "zone",
    },
    159 : {
    "label" : "Alarm, Low temperature",
    "type"  : "zone",
    },
    161 : {
    "label" : "Alarm, Loss of air flow",
    "type"  : "zone",
    },
    162 : {
    "label" : "Alarm, Carbon Monoxide Detected",
    "type"  : "zone",
    },
    163 : {
    "label" : "Alarm, Tank Level",
    "type"  : "zone",
    },

    300 : {
    "label" : "System Trouble",
    "type"  : "zone",
    },
    301 : {
    "label" : "AC Power",
    "type"  : "zone",
    },
    302 : {
    "label" : "Low System Battery/Battery Test Fail",
    "type"  : "zone",
    },
    303 : {
    "label" : "RAM Checksum Bad",
    "type"  : "zone",
    },
    304 : {
    "label" : "ROM Checksum Bad",
    "type"  : "zone",
    },
    305 : {
    "label" : "System Reset",
    "type"  : "zone",
    },
    306 : {
    "label" : "Panel programming changed",
    "type"  : "zone",
    },
    307 : {
    "label" : "Self-test failure",
    "type"  : "zone",
    },
    308 : {
    "label" : "System shutdown",
    "type"  : "zone",
    },
    309 : {
    "label" : "Battery test failure",
    "type"  : "zone",
    },
    310 : {
    "label" : "Ground fault",
    "type"  : "zone",
    },
    311 : {
    "label" : "Battery Missing/Dead",
    "type"  : "zone",
    },
    312 : {
    "label" : "Power Supply Overcurrent",
    "type"  : "zone",
    },
    313 : {
    "label" : "Engineer Reset",
    "type"  : "user",
    },
    321 : {
    "label" : "Bell/Siren Trouble",
    "type"  : "zone",
    },
    333 : {
    "label" : "Trouble or Tamper Expansion Module",
    "type"  : "zone",
    },
    341 : {
    "label" : "Trouble, ECP Cover Tamper",
    "type"  : "zone",
    },
    344 : {
    "label" : "RF Receiver Jam",
    "type"  : "zone",
    },
    351 : {
    "label" : "Telco Line Fault",
    "type"  : "zone",
    },
    353 : {
    "label" : "Long Range Radio Trouble",
    "type"  : "zone",
    },
    373 : {
    "label" : "Fire Loop Trouble",
    "type"  : "zone",
    },
    374 : {
    "label" : "Exit Error Alarm",
    "type"  : "zone",
    },
    380 : {
    "label" : "Global Trouble, Trouble Day/Night",
    "type"  : "zone",
    },
    381 : {
    "label" : "RF Supervision Trouble",
    "type"  : "zone",
    },
    382 : {
    "label" : "Supervision Auxillary Wire Zone",
    "type"  : "zone",
    },
    383 : {
    "label" : "RF Sensor Tamper",
    "type"  : "zone",
    },
    384 : {
    "label" : "RF Sensor Low Battery",
    "type"  : "zone",
    },
    393 : {
    "label" : "Clean Me",
    "type"  : "zone",
    },

    401 : {
    "label" : "AWAY/MAX",
    "type"  : "user",
    },
    403 : {
    "label" : "Scheduled Arming",
    "type"  : "user",
    },
    406 : {
    "label" : "Cancel by User",
    "type"  : "user",
    },
    407 : {
    "label" : "Remote Arm/Disarm (Downloading)",
    "type"  : "user",
    },
    408 : {
    "label" : "Quick AWAY/MAX",
    "type"  : "user",
    },
    409 : {
    "label" : "AWAY/MAX Keyswitch",
    "type"  : "user",
    },
    411 : {
    "label" : "Callback Requested",
    "type"  : "user",
    },
    412 : {
    "label" : "Success-Download/Access",
    "type"  : "user",
    },
    413 : {
    "label" : "Unsuccessful Access",
    "type"  : "user",
    },
    414 : {
    "label" : "System Shutdown",
    "type"  : "user",
    },
    415 : {
    "label" : "Dialer Shutdown",
    "type"  : "user",
    },
    416 : {
    "label" : "Successful Upload",
    "type"  : "user",
    },
    421 : {
    "label" : "Access Denied",
    "type"  : "user",
    },
    422 : {
    "label" : "Access Granted",
    "type"  : "user",
    },
    423 : {
    "label" : "PANIC Forced Access",
    "type"  : "zone",
    },
    424 : {
    "label" : "Egress Denied",
    "type"  : "user",
    },
    425 : {
    "label" : "Egress Granted",
    "type"  : "user",
    },
    426 : {
    "label" : "Access Door Propped Open",
    "type"  : "zone",
    },
    427 : {
    "label" : "Access Point DSM Trouble",
    "type"  : "zone",
    },
    428 : {
    "label" : "Access Point RTE Trouble",
    "type"  : "zone",
    },
    429 : {
    "label" : "Access Program Mode Entry",
    "type"  : "user",
    },
    430 : {
    "label" : "Access Program Mode Exit",
    "type"  : "user",
    },
    431 : {
    "label" : "Access Threat Level Change",
    "type"  : "user",
    },
    432 : {
    "label" : "Access Relay/Triger Failure",
    "type"  : "zone",
    },
    433 : {
    "label" : "Access RTE Shunt",
    "type"  : "zone",
    },
    434 : {
    "label" : "Access DSM Shunt",
    "type"  : "zone",
    },
    441 : {
    "label" : "STAY/INSTANT",
    "type"  : "user",
    },
    442 : {
    "label" : "STAY/INSTANT Keyswitch",
    "type"  : "user",
    },

    570 : {
    "label" : "Zone Bypass",
    "type"  : "zone",
    },

    574 : {
    "label" : "Group Bypass",
    "type"  : "user"
    },

    601 : {
    "label" : "Operator Initiated Dialer Test",
    "type"  : "user",
    },
    602 : {
    "label" : "Periodic Test",
    "type"  : "zone",
    },
    606 : {
    "label" : "AAV to follow",
    "type"  : "zone",
    },
    607 : {
    "label" : "Walk Test",
    "type"  : "user",
    },
    623 : {
    "label" : "Event Log 80% Full",
    "type"  : "zone",
    },
    625 : {
    "label" : "Real-Time Clock Changed",
    "type"  : "user",
    },
    627 : {
    "label" : "Program Mode Entry",
    "type"  : "zone",
    },
    628 : {
    "label" : "Program Mode Exit",
    "type"  : "zone",
    },
    629 : {
    "label" : "1-1/3 Day No Event",
    "type"  : "zone",
    },
    642 : {
    "label" : "Latch Key",
    "type"  : "user",
    },
}

evl_ResponseTypes = {
    'Login:' :  {'name' : 'Login Prompt', 'description' : 'Sent During Session Login Only.', 'handler' : 'login'},
    'OK' : {'name' : 'Login Success', 'description' : 'Send During Session Login Only, successful login', 'handler' : 'login_success'},
    'FAILED' : {'name' : 'Login Failure', 'description' : 'Sent During Session Login Only, password not accepted', 'handler' : 'login_failure'},
    'Timed Out!' : {'name' : 'Login Interaction Timed Out', 'description' : 'Sent during Session Login Only, socket connection is then closed', 'handler' : 'login_timeout'},
    '%00' : {'name' : 'Virtual Keypad Update', 'description' : 'The panel wants to update the state of the keypad','handler' : 'keypad_update'},
    '%01' : {'type' : 'zone', 'name' : 'Zone State Change', 'description' : 'A zone change-of-state has occurred', 'handler' : 'zone_state_change'},
    '%02' : {'type' : 'partition', 'name' : 'Partition State Change', 'description' : 'A partition change-of-state has occured', 'handler' : 'partition_state_change'},
    '%03' : {'type' : 'system', 'name' : 'Realtime CID Event', 'description' : 'A system event has happened that is signaled to either the Envisalerts servers or the central monitoring station', 'handler' : 'realtime_cid_event'},
    '%FF' : {'name' : 'Envisalink Zone Timer Dump', 'description' : 'This command contains the raw zone timers used inside the Envisalink. The dump is a 256 character packed HEX string representing 64 UINT16 (little endian) zone timers. Zone timers count down from 0xFFFF (zone is open) to 0x0000 (zone is closed too long ago to remember). Each ''tick'' of the zone time is actually 5 seconds so a zone timer of 0xFFFE means ''5 seconds ago''. Remember, the zone timers are LITTLE ENDIAN so the above example would be transmitted as FEFF.'},
    '^00' : {'type' : 'envisalink', 'name': 'Poll', 'description' : 'Envisalink poll'},
    '^01' : {'type' : 'envisalink', 'name': 'Change Default Partition', 'description': 'Change the partition which keystrokes are sent to when using the virtual keypad.'},
    '^02' : {'type' : 'envisalink', 'name': 'Dump Zone Timers', 'description' : 'This command contains the raw zone timers used inside the Envisalink. The dump is a 256 character packed HEX string representing 64 UINT16 (little endian) zone timers. Zone timers count down from 0xFFFF (zone is open) to 0x0000 (zone is closed too long ago to remember). Each ''tick'' of the zone time is actually 5 seconds so a zone timer of 0xFFFE means ''5 seconds ago''. Remember, the zone timers are LITTLE ENDIAN so the above example would be transmitted as FEFF.'},
}
 
    # 500 : {'name' : 'Command Acknowledge', 'description' : 'A command has been received successfully.'},
    # 501 : {'name' : 'Command Error', 'description' : 'A command has been received with a bad checksum.'},
    # 502 : {'name' : 'System Error {0}', 'description' : 'An error has been detected.'},
    # 505 : {'name' : 'Login Interaction', 'description' : 'Sent During Session Login Only.', 'handler' : 'login'},
    # 510 : {'name' : 'Keypad Led State - Partition 1', 'description' : 'Outputted when the TPI has deceted a change of state in the Partition 1 keypad LEDs.'},
    # 511 : {'name' : 'Keypad Led Flash State - Partition 1', 'description' : 'Outputed when the TPI has detected a change of state in the Partition 1 keypad LEDs as to whether to flash or not. Overrides 510. That is, if 511 says the PROGRAM LED is flashing, then it doesn''t matter what 510 says.'},
    # 550 : {'name' : 'Time/Date Broadcast', 'description' : 'Outputs the current security system time.'},
    # 560 : {'name' : 'Ring Detected', 'description' : 'The Panel has detected a ring on the telephone line. Note: This command will only be issued if an ESCORT 5580xx module is present.'},
    # 561 : {'name' : 'Indoor Temperature Broadcast', 'description' : 'If an ESCORT 5580TC is installed, and at least one ENERSTAT thermostat, this command displays the interior temperature and the thermostat number.'},
    # 562 : {'name' : 'Outdoor Temperature Broadcast', 'description' : 'If an ESCORT 5580TC is installed, and at least one ENERSTAT thermostat, this command displays the exterior temperature and the thermostat number.'},
    # 601 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Alarm', 'description' : 'A zone has gone into alarm.', 'handler' : 'zone', 'status' : {'alarm' : True}},
    # 602 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Alarm Restore', 'description' : 'A zone alarm has been restored.', 'handler' : 'zone', 'status' : {'alarm' : False}},
    # 603 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Tamper', 'description' : 'A zone has a tamper condition.', 'handler' : 'zone', 'status' : {'tamper' : True}},
    # 604 : {'type' : 'zone', 'name' : 'Partition {0[0]} Zone {0[1]}{0[2]}{0[3]} Tamper Restore', 'description' : 'A zone tamper condition has been restored.', 'handler' : 'zone', 'status' : {'tamper' : False}},
    # 605 : {'type' : 'zone', 'name' : 'Zone {0} Fault', 'description' : 'A zone has a fault condition.', 'status' : {'fault' : True}},
    # 606 : {'type' : 'zone', 'name' : 'Zone {0} Fault Restore', 'description' : 'A zone fault condition has been restored.', 'status' : {'fault' : False}},
    # 609 : {'type' : 'zone', 'name' : 'Zone {0} Open', 'description' : 'General status of the zone.', 'status' : {'open' : True}},
    # 610 : {'type' : 'zone', 'name' : 'Zone {0} Restored', 'description' : 'General status of the zone.', 'status' : {'open' : False}},
    # 615 : {'name' : 'Envisalink Zone Timer Dump', 'description' : 'This command contains the raw zone timers used inside the Envisalink. The dump is a 256 character packed HEX string representing 64 UINT16 (little endian) zone timers. Zone timers count down from 0xFFFF (zone is open) to 0x0000 (zone is closed too long ago to remember). Each ''tick'' of the zone time is actually 5 seconds so a zone timer of 0xFFFE means ''5 seconds ago''. Remember, the zone timers are LITTLE ENDIAN so the above example would be transmitted as FEFF.'},
    # 620 : {'name' : 'Duress Alarm', 'description' : 'A duress code has been entered on a system keypad.'},
    # 621 : {'type' : 'system', 'name' : '[F] Key Alarm', 'description' : 'A Fire key alarm has been detected.', 'status' : {'fire_key_alarm' : True}},
    # 622 : {'type' : 'system', 'name' : '[F] Key Alarm', 'description' : 'A Fire key alarm has been restored (sent automatically).', 'status' : {'fire_key_alarm' : False}},
    # 623 : {'type' : 'system', 'name' : '[A] Key Alarm', 'description' : 'A Auxillary key alarm has been detected.', 'status' : {'aux_key_alarm' : True}},
    # 624 : {'type' : 'system', 'name' : '[A] Key Alarm', 'description' : 'A Auxillary key alarm has been restored (sent automatically).', 'status' : {'aux_key_alarm' : False}},
    # 625 : {'type' : 'system', 'name' : '[P] Key Alarm', 'description' : 'A Panic key alarm has been detected.', 'status' : {'panic_key_alarm' : True}},
    # 626 : {'type' : 'system', 'name' : '[P] Key Alarm', 'description' : 'A Panic key alarm has been restored (sent automatically).', 'status' : {'panic_key_alarm' : False}},
    # 631 : {'type' : 'system', 'name' : '2-Wire Smoke/Aux Alarm', 'description' : 'A 2-wire smoke/Auxiliary alarm has been activated.', 'status' : {'2wire_alarm' : True}},
    # 632 : {'type' : 'system', 'name' : '2-Wire Smoke/Aux Restore', 'description' : 'A 2-wire smoke/Auxiliary alarm has been restored.', 'status' : {'2wire_alarm' : False}},
    # 650 : {'type' : 'partition', 'name' : 'Partition {0} Ready', 'description' : 'Partition can now be armed (all zones restored, no troubles, etc). Also issued at the end of Bell Timeout if the partition was READY when an alarm occurred.', 'status' : {'ready' : True, 'pgm_output' : False}},
    # 651 : {'type' : 'partition', 'name' : 'Partition {0} Not Ready', 'description' : 'Partition cannot be armed (zones open, trouble present, etc).', 'status' : {'ready' : False}},
    # 652 : {'type' : 'partition', 'name' : 'Partition {0} Armed Mode {1}', 'description' : 'Partition has been armed - sent at the end of exit delay Also sent after an alarm if the Bell Cutoff Timer expires Mode is appended to indicate whether the partition is armed AWAY, STAY, ZERO-ENTRY-AWAY, or ZERO-ENTRY-STAY.', 'handler' : 'partition', 'status' : {'armed' : True, 'exit_delay' : False}},
    # 653 : {'type' : 'partition', 'name' : 'Partition {0} Ready - Force Arming Enabled', 'description' : 'Partition can now be armed (all zones restored, no troubles, etc). Also issued at the end of Bell Timeout if the partition was READY when an alarm occurred.', 'status' : {'ready' : True}},
    # 654 : {'type' : 'partition', 'name' : 'Partition {0} In Alarm', 'description' : 'A partition is in alarm.', 'status' : {'alarm' : True}},
    # 655 : {'type' : 'partition', 'name' : 'Partition {0} Disarmed', 'description' : 'A partition has been disarmed.', 'status' : {'alarm' : False, 'armed' : False, 'exit_delay' : False, 'entry_delay' : False}},
    # 656 : {'type' : 'partition', 'name' : 'Partition {0} Exit Delay in Progress', 'description' : 'A partition is in Exit Delay.', 'status' : {'exit_delay' : True}},
    # 657 : {'type' : 'partition', 'name' : 'Partition {0} Entry Delay in Progress', 'description' : 'A partition is in Entry Delay.', 'status' : {'entry_delay' : True}},
    # 658 : {'type' : 'partition', 'name' : 'Partition {0} Keypad Lock-out', 'description' : 'A partition is in Keypad Lockout due to too many failed user code attempts.'},
    # 659 : {'type' : 'partition', 'name' : 'Partition {0} Failed to Arm', 'description' : 'An attempt to arm the partition has failed.'},
    # 660 : {'type' : 'partition', 'name' : 'Partition {0} PGM Output is in Progress', 'description' : '*71, *72, *73, or *74 has been pressed.', 'status': {'pgm_output' : True}},
    # 663 : {'type' : 'partition', 'name' : 'Partition {0} Chime Enabled', 'description' : 'The door chime feature has been enabled.', 'status' : {'chime' : True}},
    # 664 : {'type' : 'partition', 'name' : 'Partition {0} Chime Disabled', 'description' : 'The door chime feature has been disabled.', 'status' : {'chime' : False}},
    # 670 : {'type' : 'partition', 'name' : 'Partition {0} Invalid Access Code', 'description' : 'Invalid Access Code.'},
    # 671 : {'type' : 'partition', 'name' : 'Partition {0} Function Not Available', 'description' : 'A partition is in Entry delay.'},
    # 672 : {'type' : 'partition', 'name' : 'Partition {0} Failure to Arm', 'description' : 'An attempt was made to arm the partition and it failed.'},
    # 673 : {'type' : 'partition', 'name' : 'Partition {0} is Busy', 'description' : 'The partition is busy (another keypad is programming or an installer is programming).'},
    # 674 : {'type' : 'partition', 'name' : 'Partition {0} System Arming in Progress', 'description' : 'This system is auto-arming and is in arm warning delay.'},
    # 680 : {'name' : 'System in installers mode', 'description' : 'System has entered installers mode'},
    # 700 : {'type' : 'partition', 'name' : 'Partition {0} User {1} Closing', 'description' : 'A partition has been armed by a user - sent at the end of exit delay.', 'handler' : 'partition', 'status' : {'armed' : True, 'exit_delay' : False}},
    # 701 : {'type' : 'partition', 'name' : 'Partition {0} Special Closing', 'description' : 'A partition has been armed by one of the following methods: Quick Arm, Auto Arm, Keyswitch, DLS software, Wireless Key.', 'status' : {'armed' : True, 'exit_delay' : False}},
    # 702 : {'type' : 'partition', 'name' : 'Partition {0} Partial Closing', 'description' : 'A partition has been armed but one or more zones have been bypassed.', 'status' : {'armed' : True, 'exit_delay' : False}},
    # 750 : {'type' : 'partition', 'name' : 'Partition {0} User {1} Opening', 'description' : 'A partition has been disarmed by a user.', 'handler' : 'partition', 'status' : {'armed' : False, 'entry_delay' : False}},
    # 751 : {'type' : 'partition', 'name' : 'Partition {0} Special Opening', 'description' : 'A partition has been disarmed by one of the following methods: Keyswitch, DLS software, Wireless Key.',  'status' : {'armed' : False, 'entry_delay' : False}},
    # 800 : {'type' : 'system', 'name' : 'Panel Battery Trouble', 'description' : 'The panel has a low battery.', 'status' : {'battery_trouble' : True}},
    # 801 : {'type' : 'system', 'name' : 'Panel Battery Trouble Restore', 'description' : 'The panel''s low battery has been restored.', 'status' : {'battery_trouble' : False}},
    # 802 : {'type' : 'system', 'name' : 'Panel AC Trouble', 'description' : 'AC power to the panel has been removed.', 'status' : {'ac_trouble' : True}},
    # 803 : {'type' : 'system', 'name' : 'Panel AC Restore', 'description' : 'AC power to the panel has been restored.', 'status' : {'ac_trouble' : False}},
    # 806 : {'type' : 'system', 'name' : 'System Bell Trouble', 'description' : 'An open circuit has been detected across the bell terminals.', 'status' : {'system_bell_trouble' : True}},
    # 807 : {'type' : 'system', 'name' : 'System Bell Trouble Restoral', 'description' : 'The bell trouble has been restored.', 'status' : {'system_bell_trouble' : False}},
    # 814 : {'name' : 'FTC Trouble', 'description' : 'The panel has failed to communicate successfully to the monitoring.'},
    # 816 : {'name' : 'Buffer Near Full', 'description' : 'Sent when the panel''s Event Buffer is 75% full from when it was last uploaded to DLS.'},
    # 829 : {'type' : 'system', 'name' : 'General System Tamper', 'description' : 'A tamper has occurred with one of the following modules: Zone Expander, PC5132, PC5204, PC5208, PC5400, PC59XX, LINKS 2X50, PC5108L, PC5100, PC5200.', 'status' : {'system_tamper' : True}},
    # 830 : {'type' : 'system', 'name' : 'General System Tamper Restore', 'description' : 'A general system Tamper has been restored.', 'status' : {'system_tamper' : False}},
    # 840 : {'type' : 'partition', 'name' : 'Partition {0} Trouble LED ON', 'description' : 'This command shows the general trouble status that the trouble LED on a keypad normally shows. When ON, it means there is a trouble on this partition. This command when the LED transitions from OFF, to ON.', 'status' : {'trouble' : True}},
    # 841 : {'type' : 'partition', 'name' : 'Partition {0} Trouble LED OFF', 'description' : 'This command shows the general trouble status that the trouble LED on a keypad normally shows. When the LED is OFF, this usually means there are no troubles present on this partition but certain modes will blank this LED even in the presence of a partition trouble. This command when the LED transitions from ON, to OFF.', 'status' : {'trouble' : False}},
    # 842 : {'type' : 'system', 'name' : 'Fire Trouble Alarm', 'description' : 'Fire Trouble Alarm', 'status' : {'fire_trouble' : True}},
    # 843 : {'type' : 'system', 'name' : 'Fire Trouble Alarm Restore', 'description' : 'Fire Trouble Alarm Restore', 'status' : {'fire_trouble' : False}},
    # 849 : {'name' : 'Verbose Trouble Status', 'description' : 'This command is issued when a trouble appears on the system and roughly every 5 minutes until the trouble is cleared. The two characters are a bitfield (similar to 510,511). The meaning of each bit is the same as what you see on an LED keypad (see the user manual).'},
    # 900 : {'name' : 'Code Required', 'description' : 'This command will tell the API to enter an access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'},
    # 912 : {'name' : 'Command Output Pressed', 'description' : 'This command will tell the API to enter an access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'},
    # 921 : {'name' : 'Master Code Required', 'description' : 'This command will tell the API to enter a master access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'},
    # 922 : {'name' : 'Installers Code Required', 'description' : 'This command will tell the API to enter an installers access code. Once entered, the 200 command will be sent to perform the required action. The code should be entered within the window time of the panel.'},    
 # }
