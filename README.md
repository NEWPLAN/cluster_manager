# cluster_manager
a python3-based wrapper to submitted task to the remote clusters. it supports three basic functions as follows.

### synchronous execution:
if you want to execute a command (e.g., cd XXXXX; make build; echo DONE;), you could use the following script:
```python3 ssh_controller.py --cmd="cd XXXXX; make build; echo DONE;" --allow_print="g13"```, the script would help you printed the execution result until all commands are executed.
If you want to run the command in sudo mode, you could append ```--sudo``` in the above script.
### asynchronous execution:
using the above task as an example,  you could use the following script:
```python3 ssh_controller.py --cmd="cd XXXXX; make build; echo DONE;" --allow_print="g13" --interactive```, the script would help you printed the execution result once there are output in the remote
### sftp
It allows the user to sync files from a local path (indicated by ```--sync_path```) to the remote clusters (the same path)
```python3 ssh_controller.py --sync --sync_path="XXXXX"```

