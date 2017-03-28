import os
import threading
import time

from mock import MagicMock
from logentries.followers import Follower
from logentries.le import _init_entry_identifier
from logentries.le import formats


def mock_state_object():
    state = {"filename":"test.log", "position":0}
    return state

def execute_follower(transport, state, config, filter, identifier):
    formatter = formats.get_formatter('syslog', "myhost", "Web", "89caf699-8fb7-45b1-a41f-ae111ec99148")
    follower = Follower("test_follower", filter, formatter, identifier, transport, state, config)
    follower._load_state(state)
    time.sleep(10) 
    follower.close()

def test_default_identifier(capsys):
    with open('test.log', 'w') as f:
        f.write('First message')

    mock_transport = MagicMock()
    mock_state = mock_state_object()
    mock_config = MagicMock()

    identifier = _init_entry_identifier('')
    thread = threading.Thread(target=execute_follower(mock_transport, mock_state, mock_config, lambda a: a, identifier))
    thread.daemon = True
    thread.start()

    out, err = capsys.readouterr()

    try:
        os.remove("test.log")
    except OSError:
        pass


    assert "89caf699-8fb7-45b1-a41f-ae111ec99148<14>1 " in err
    assert "myhost Web - - - First message" in err
    