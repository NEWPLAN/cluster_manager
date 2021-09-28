# cluster_manager
A python3-based wrapper to submit execution task to the remote clusters. It supports three basic functions as follows.

### synchronous execution:
if you want to execute a command (e.g., cd XXXXX; make build; echo DONE;), you could use the following script:
```python3 ssh_controller.py --cmd="cd XXXXX; make build; echo DONE;" --allow_print="g13"```, the script would help you printed the execution result until all commands are executed.
If you want to run the command in sudo mode, you could append ```--sudo``` in the above script.
### asynchronous execution:
using the above task as an example,  you could use the following script:
```python3 ssh_controller.py --cmd="cd XXXXX; make build; echo DONE;" --allow_print="g13" --interactive```, the script would help you printed the execution result once there are output in the remote
### sftp
It allows the user to sync files from a local path (indicated by ```--sync_path```) to the remote clusters (the same path)
``` bash
python3 ssh_controller.py --sync --sync_path="XXXXX"
```


# How to use (Examples)
### Upload files (broadcast)
``` bash
### brodcast folder from local to remote(cluster)
ssh_controller.py --sync --sync_path="PATH_TO_YOUR_FOLDER"
```
### Multiple cmds together
``` shell
## using sudo to execute some cmd in cluster
 ssh_controller.py --cmd="mlnx_qos -i eth2 | grep enabled" --allow_print="all" --sudo
```

### Execute in interactive mode
``` bash
python3 ssh_controller.py --cmd='cd /mesh_comm_service; RCL_MAX_VLOG_LEVEL=2 ./build/mesh_comm_service --cluster 12.12.12.111 12.12.12.112 12.12.12.113 12.12.12.114 12.12.12.115 12.12.12.116 12.12.12.110 12.12.12.109 12.12.12.108 12.12.12.107 12.12.12.106 12.12.12.105 12.12.12.104 12.12.12.103 12.12.12.102 12.12.12.101' --alow_print="g11" --interactive
```

# Some other cmds

``` bash 
### if you want to kill some threads, you could use as --cmd=
ps -aux | grep mesh_comm_service | grep -v ssh | awk \'{print $2}\' | xargs kill
```

# arguments:

- **usage**: 
  ``` bash
   ssh_controller.py [-h] [--H H] [--cmd CMD] [--sync] [--sync_path SYNC_PATH] 
   [--sudo] [--user USER] [--passwd PASSWD] [--port PORT] [--host HOST] 
   [--allow_print ALLOW_PRINT] [--interactive] [--use_glog] [--env ENV] 
   [--enable_full_log]
    ```



- **optional arguments**:

| cmds                      | Description                                                           | Tested |
| ------------------------- | --------------------------------------------------------------------- | ------ |
| -h, --help                | show this help message and exit                                       | Yes    |
| --H H                     | host ID [1,2,3,4,5]                                                   | No     |
| --cmd CMD                 | executing your command                                                | Yes    |
| --sync                    | Sync data                                                             | Yes    |
| --sync_path SYNC_PATH     | The path of folder to sync                                            | Yes    |
| --sudo                    | executing your command <br>  working under sudo mode                  | Yes    |
| --user USER               | username to login                                                     | No     |
| --passwd PASSWD           | password to login                                                     | No     |
| --port PORT               | the port of ssh service                                               | No     |
| --host HOST               | the host ip for this session                                          | No     |
| --allow_print ALLOW_PRINT | the node to display the ret, split by ',' or all to show all the node | Yes    |
| --interactive             | working under interactive mode                                        | Yes    |
| --use_glog                | enable glog as logger or not                                          | Yes    |
| --env ENV                 | speficy the environment for execution                                 | No     |
| --enable_full_log         | enable full log for other module                                      | Yes    |



