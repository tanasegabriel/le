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


def execute_follower(transport, state, config, filter, formatter, identifier):
    follower = Follower("test_follower", filter, formatter, identifier, transport, state, config)
    follower._load_state(state)
    time.sleep(10) 
    follower.close()

def test_default_formatter(capsys):
    with open('test.log', 'w') as f:
        f.write('First message')
        f.write('Second message')

    mock_transport = MagicMock()
    mock_state = mock_state_object()
    mock_config = MagicMock()

    formatter = formats.get_formatter('plain', "myhost", "logname", "")
    identifier = _init_entry_identifier('')
    thread = threading.Thread(target=execute_follower(mock_transport, mock_state, mock_config, lambda a: a, formatter, identifier))
    thread.daemon = True
    thread.start()

    out, err = capsys.readouterr()

    try:
        os.remove("test.log")
    except OSError:
        pass

    assert "First message" in err
    assert "Second message" in err

    
def test_syslog_formatter(capsys):
    with open('test.log', 'w') as f:
        f.write('First message')

    mock_transport = MagicMock()
    mock_state = mock_state_object()
    mock_config = MagicMock()

    formatter = formats.get_formatter('syslog', "myhost", "log", "89caf699-8fb7-45b1-a41f-ae111ec99148")
    identifier = _init_entry_identifier('')
    thread = threading.Thread(target=execute_follower(mock_transport, mock_state, mock_config, lambda a: a, formatter, identifier))
    thread.daemon = True
    thread.start()

    out, err = capsys.readouterr()

    try:
        os.remove("test.log")
    except OSError:
        pass

    assert "89caf699-8fb7-45b1-a41f-ae111ec99148<14>1 " in err
    assert "myhost log - - - First message" in err
    
def test_custom_formatters(capsys):
    with open('test.log', 'w') as f:
        f.write('First message')

    mock_transport = MagicMock()
    mock_state = mock_state_object()
    mock_config = MagicMock()

    formatter = formats.get_formatter('abrakadabra $hostname $line', "myhost", "log", "89caf699-8fb7-45b1-a41f-ae111ec99148")
    identifier = _init_entry_identifier('')
    thread = threading.Thread(target=execute_follower(mock_transport, mock_state, mock_config, lambda a: a, formatter, identifier))
    thread.daemon = True
    thread.start()

    out, err = capsys.readouterr()

    try:
        os.remove("test.log")
    except OSError:
        pass

    assert "abrakadabra myhost First message" in err
    
def test_user_formatters():
    assert True
    