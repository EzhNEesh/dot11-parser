import re

frame_types = {
    '00': 'Association request',
    '20': 'Reassociation request',
    '40': 'Probe request',
    '60': 'Timing advertisement',
    '80': 'Beacon',
    'a0': 'Disassociation',
    'c0': 'Deauthentication',
    'b0': 'Authentication',
    'e0': 'Action',
    '10': 'Association response',
    '30': 'Reassociation response',
    '50': 'Probe response',
    '70': 'Reserved',
    '44': 'Beamforming Report Poll',
    '54': 'VHT/HE NDP Announcement',
    '64': 'Control Frame Extension',
    '74': 'Control wrapper',
    '84': 'Block ACK Request',
    '94': 'Block ACK',
    'a4': 'PS-Poll',
    'b4': 'RTS',
    'c4': 'CTS',
    'd4': 'ACK',
    'e4': 'CF-End',
    'f4': 'CF-END+CF-ACK',
    '08': 'Data',
    '18': 'Data + CF-ACK',
    '28': 'Data + CF-Poll',
    '38': 'Data + CF-ACK + CF-Poll',
    '48': 'Null (no data)',
    '58': 'CF-ACK (no data)',
    '68': 'CF-Poll (no data)',
    '78': 'CF-ACK + CF-Poll (no data)',
    '88': 'QoS Data',
    '98': 'QoS Data + CF-ACK',
    'a8': 'QoS Data + CF-Poll',
    'b8': 'QoS Data + CF-ACK + CF-Poll',
    'c8': 'QoS Null (no data)',
    'd8': 'Reserved',
    'e8': 'QoS CF-Poll (no data)',
    'f8': 'QoS CF-ACK + CF-Poll (no data)',
}


def validate_frame_subtype(frame_control_field: str) -> str:
    return frame_types[frame_control_field]


def is_drone(ssid):
    return re.search('.*drone.*', ssid.lower()) is not None
