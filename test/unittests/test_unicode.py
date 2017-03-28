import os 
import threading
import time

from mock import MagicMock
from logentries.followers import Follower

def execute_follower(transport, state, config):
    follower = Follower("test_follower", lambda a: a, lambda a: a, '', transport, state, config)
    follower._load_state(state)
    time.sleep(10) 
    follower.close()


def test_unicode(capsys):
    with open('test.log', 'w') as f:
        f.write('Message: ěščřžýáíéů')

    mock_transport = MagicMock()
    mock_state = mock_state_object()
    mock_config = MagicMock()

    thread = threading.Thread(target=execute_follower(mock_transport, mock_state, mock_config))
    thread.daemon = True
    thread.start()
    
    out, err = capsys.readouterr()
    
    assert "Message: ěščřžýáíéů" in err
    
    try:
        os.remove("test.log")
    except OSError:
        pass
    

def mock_state_object():
    state = {"filename":"test.log", "position":0}
    return state
