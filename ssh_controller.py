#! /usr/bin/env python3

import multiprocessing as mp

import time
import os
import argparse
import paramiko
import json

import netifaces as nf


def ipv4_addresses():
    ip_list = []
    for interface in nf.interfaces():
        for link in nf.ifaddresses(interface).get(nf.AF_INET, ()):
            ip_list.append(link["addr"])
    return ip_list


def ipv6_addresses():
    ip_list = []
    for interface in nf.interfaces():
        for link in nf.ifaddresses(interface).get(nf.AF_INET6, ()):
            ip_list.append(link["addr"])
    return ip_list


def is_local(ip):
    return ip in ipv4_addresses() + ipv6_addresses()


parser = argparse.ArgumentParser()
parser.add_argument("--H", type=str, help="host ID [1,2,3,4,5]")
parser.add_argument("--cmd", type=str, default="", help="executing your command")
parser.add_argument("--sync", action="store_true", help="Sync data")
parser.add_argument("--sync_path", type=str, default="", help="executing your command")
parser.add_argument("--sudo", action="store_true", help="working under sudo mode")
parser.add_argument("--user", type=str, default="newplan", help="username to login")
parser.add_argument("--passwd", type=str, default=" ", help="password to login")
parser.add_argument("--port", type=int, default=22, help="the port of ssh service")
parser.add_argument("--host", type=str, default="", help="the host ip for this session")
parser.add_argument(
    "--allow_print",
    type=str,
    default="",
    help="the node to display the ret, split by ',' or all to show all the node ",
)

parser.add_argument(
    "--interactive", action="store_true", help="working under interactive mode"
)
parser.add_argument(
    "--use_glog", action="store_true", help="enable glog as logger or not"
)
parser.add_argument(
    "--env",
    type=str,
    default="/home/newplan/.software",
    help="speficy the environment for execution",
)

parser.add_argument(
    "--enable_full_log", action="store_true", help="enable full log for other module"
)


args = parser.parse_args()


# select which log to use
if args.use_glog:
    import glog as logger
else:
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s: %(asctime)s %(filename)s:%(lineno)d] \t%(message)s",
    )
    # format='[%(levelname)s: %(asctime)s %(thread)d %(funcName)s %(filename)s:%(lineno)d] \t%(message)s'
    logger = logging.getLogger(__name__)


if not args.enable_full_log and not args.use_glog:
    from importlib import reload

    logging.shutdown()
    reload(logging)


class SshClientImpl:
    "A wrapper of paramiko.SSHClient"
    TIMEOUT = 4  # by default, the maximum time to wait for an ssh connection is 4s

    def __init__(self, host, port, username, password, key=None, passphrase=None):
        self.username = username
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = host
        self.port = port
        self._ssh_interactive = None

        self.client.connect(
            host,
            port,
            username=username,
            password=password,
            pkey=key,
            timeout=self.TIMEOUT,
        )

    def using_interactive_channel(self, cmd):
        # ref https://blog.csdn.net/weixin_39912556/article/details/80587180
        if self._ssh_interactive is None:
            self._ssh_interactive = self.client.invoke_shell()
            self._ssh_interactive.settimeout(90)
        try:
            self._ssh_interactive.send(cmd + "\r")
        except Exception as e:
            logger.error(f"Error of executing {cmd}, error: {e}")

    def querying_interactive_channel(self):
        assert self._ssh_interactive is not None, (
            "Invalid ssh interactive channel, "
            "please using 'using_interactive_channel' "
            f"to submit the command to {self.host}:{self.port}"
        )

        cnt = 0
        while not self._ssh_interactive.recv_ready():
            time.sleep(0.1)
            cnt += 1
            if cnt > 10:
                return None

        try:
            ret_str = self._ssh_interactive.recv(32768).decode("utf-8")
        except Exception as e:
            logger.error(
                f"node({self.host}:{self.port}) unknown error for execution"
                f", for reason: {e}"
            )
        return ret_str

    def get_interactive_channel(self):
        return self._ssh_interactive

    def get_channel(self):
        return self.client

    def close(self):
        if self.client is not None:
            self.client.close()
            self.client = None

    def load_env(self, env=args.env):
        env = env.strip()
        if len(env) == 0:
            return " set -e; "  # return immediately if error

        if env[-1] == ";":
            env = env[:-2]

        if env[-1] == "/":
            env = env[:-2]

        BASE_PREFIX = env

        LIBRARY_PATH = f'export LIBRARY_PATH="{BASE_PREFIX}/lib:{BASE_PREFIX}/lib64:$LIBRARY_PATH";'
        LD_LIBRARY_PATH = f'export LD_LIBRARY_PATH="{BASE_PREFIX}/lib:{BASE_PREFIX}/lib64:$LD_LIBRARY_PATH";'
        PATH = f'export PATH="{BASE_PREFIX}/bin:$PATH";'

        C_INCLUDE_PATH = (
            f'export C_INCLUDE_PATH="{BASE_PREFIX}/include:$C_INCLUDE_PATH";'
        )

        CPLUS_INCLUDE_PATH = (
            f'export CPLUS_INCLUDE_PATH="{BASE_PREFIX}/include:$CPLUS_INCLUDE_PATH";'
        )

        base_env = "".join(
            [LD_LIBRARY_PATH, LIBRARY_PATH, C_INCLUDE_PATH, CPLUS_INCLUDE_PATH, PATH]
        )
        return base_env + " set -e; "  # return immediately if error

    def execute(self, command, sudo=False):
        feed_password = False

        if args.sudo:
            logger.warning("WARNING: execute with sudo")
            command = "sudo -S -p '' %s" % command
            feed_password = True

        real_execute_cmd = self.load_env() + command
        # logger.warning("Real execution cmd: {}".format(real_execute_cmd))
        stdin, stdout, stderr = self.client.exec_command(real_execute_cmd, get_pty=True)

        if args.sudo and feed_password:
            stdin.write(self.password + "\n")
            stdin.flush()
        return {
            "out": stdout.readlines(),
            "err": stderr.readlines(),
            "retval": stdout.channel.recv_exit_status(),
        }


# ref: https://www.cnblogs.com/chen/p/9493546.html
class SFTPService:
    def __init__(self, ssh_ctx):
        self.borrowed_ctx = ssh_ctx
        self._sftp_channel = paramiko.SFTPClient.from_transport(
            self.borrowed_ctx.get_channel().get_transport()
        )
        pass

    def copy_files(self, source, target):
        """ Uploads the contents of the source directory to the target path. The
            target directory needs to exists. All subdirectories in source are 
            created under target.
        """

        if source == target and is_local(self.borrowed_ctx.host):
            logger.warning("IGNORE self-node: {}".format(self.borrowed_ctx.host))
            return

        try:
            for item in os.listdir(source):
                if os.path.isfile(os.path.join(source, item)):
                    logger.debug(
                        "processing {} --> {}".format(
                            os.path.join(source, item), self.borrowed_ctx.host
                        )
                    )
                    self._sftp_channel.put(
                        os.path.join(source, item), "%s/%s" % (target, item)
                    )
                else:
                    self.mkdir("%s/%s" % (target, item), ignore_existing=True)
                    self.copy_files(
                        os.path.join(source, item), "%s/%s" % (target, item)
                    )
        except Exception as e:
            logger.warning(
                "Error of processing target = ({}:{}), for reason: {}".format(
                    self.borrowed_ctx.host, self.borrowed_ctx.port, e,
                )
            )
            exit(0)

    def mkdir(self, path, mode=1776, ignore_existing=False):
        """ Augments mkdir by adding an option to not fail if the folder exists  """
        try:
            self._sftp_channel.mkdir(path)  # , mode)
        except IOError:
            if ignore_existing:
                pass
            else:
                print("failed to process: ")
                raise

    def close(self):
        logger.warning("Closing the sftp server at {}".format(self.borrowed_ctx.host))
        self._sftp_channel.close()


class SSHClientAbst:
    def __init__(self, host, port, username, password, id):
        self.remote_host = host
        self.remote_port = port
        self.remote_username = username
        self.remote_password = password
        self.id = id

        self.parent_channel, self.child_channel = mp.Pipe()
        self.process_handler = None
        self.is_connected = False
        logger.info(f"Creating SSHClient for {host}:{port}")

    def send_command(self, command, using_sudo, interactive, allow_print):
        ################################
        allowed_cluster = [x.strip() for x in allow_print.split(",")]
        packed_task = {
            "cmd": command,
            "using_sudo": using_sudo,
            "interactive": interactive,
            "allow_print": False,
        }
        if self.id in allowed_cluster or allow_print.strip() == "all":
            packed_task["allow_print"] = True
            if interactive:
                packed_task["interactive"] = True
        else:
            packed_task["interactive"] = False

        self.parent_channel.send(json.dumps(packed_task))
        logger.debug(
            f"Send cmd({command}) to the channel "
            f"{self.remote_host}:{self.remote_port}"
        )

    def is_active(self):
        return self.is_connected is True

    def block_until_connected(self):

        logger.debug(
            "Querying the status of connection "
            f"({self.remote_host}:{self.remote_port})"
        )
        if self.is_connected is False:
            while True:
                if self.parent_channel.poll():
                    data = self.parent_channel.recv()

                    if data == "CONNECTION_IS_READY":
                        self.is_connected = True
                    elif data == "CONNECTION_IS_FAILED":
                        self.is_connected = False
                        return
                    else:
                        logger.fatal("UNKNOWN connection status")
                        exit(-1)
                    break
                else:
                    logger.info(
                        f"{self.id}({self.remote_host}:{self.remote_port})"
                        " is not ready to recv"
                    )
                    time.sleep(0.1)

        logger.info(
            f"The SSH connection ({self.remote_host}:{self.remote_port}) is ready"
        )

    def get_ret_from_channel(self):
        ret = None
        if self.parent_channel.poll():
            ret = self.parent_channel.recv()
            ret = json.loads(ret)
        return ret

    def query_command(self, command, allowed_print=True):
        while True:
            ret = self.get_ret_from_channel()
            if ret is None:
                if not args.interactive:
                    logger.warning(
                        f"{self.id}({self.remote_host}:{self.remote_port}) "
                        "has not returned the result...."
                    )
                time.sleep(1)
            else:
                break

        encounting_error = False

        if ret["status"] is False:  # encounting errors
            logger.error("Encounter an error at {}".format(self.id))
            allowed_print = True
            encounting_error = True

        if allowed_print or encounting_error:
            logger.info(
                "The result of execution cmd ({}) from {}({}:{}) is:\n{}".format(
                    ret["cmd"],
                    self.id,
                    self.remote_host,
                    self.remote_port,
                    "  ".join(ret["out"]).replace(
                        "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE\r\n", ""
                    )
                    + " ".join(ret["err"]).replace(
                        "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE\r\n", ""
                    ),
                )
            )

        return ret["status"] is True

    def ssh_remote_execution(self, io_channel):
        logger.debug(f"{self.remote_host}:{self.remote_port} works in sync mode")
        while True:
            logger.debug(
                f"{self.remote_host}:{self.remote_port} is ready, "
                "wait for cmd from master..."
            )
            if io_channel.poll():  # the upper layer has submitted new task
                recv_data = io_channel.recv()  # accept new cmd
            else:  # otherwise, continue the loops
                time.sleep(0.1)
                continue
            unpack_task = json.loads(recv_data)
            logger.debug(
                "{}:{} accepts a cmd({}) from master...".format(
                    self.remote_host, self.remote_port, unpack_task["cmd"]
                )
            )

            if unpack_task["cmd"] == "CLOSE-IMM":  # terminated right now!
                logger.debug(
                    "SSHClient({}:{}) stops services.".format(
                        self.remote_host, self.remote_port
                    )
                )
                break

            try:
                modified_cmd = unpack_task["cmd"].strip()
                if modified_cmd[-1] != ";":
                    modified_cmd += ";"
                modified_cmd += " echo EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=`expr 100 + 100`-DONE;"

                ret = self.ssh_client.execute(modified_cmd, sudo=False)
                exe_ret = {
                    "cmd": unpack_task["cmd"],
                    "out": ret["out"],
                    "err": ret["err"],
                    "status": True,
                }

                if (
                    "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE"
                    not in " ".join(ret["out"])
                ) and (
                    "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE"
                    not in " ".join(ret["err"])
                ):
                    exe_ret["status"] = False  # the cmd are not executed correctly

                io_channel.send(json.dumps(exe_ret))
                pass

            except Exception as e:
                exe_ret["status"] = False
                logger.error(
                    "Error when processing cmd=({}), node=({}:{}) : {}".format(
                        unpack_task["cmd"], self.remote_host, self.remote_port, e
                    )
                )
            finally:
                logger.debug(
                    "In deamon_execution: {}:{} recvs cmd({}) from master".format(
                        self.remote_host, self.remote_port, unpack_task["cmd"]
                    )
                )
                pass
            pass

        pass

    def ssh_remote_execution_interactive(self, io_channel):
        logger.info(f"{self.remote_host}:{self.remote_port} works in interactive mode")
        while True:
            logger.debug(
                f"{self.remote_host}:{self.remote_port} is ready, wait for cmd from master..."
            )
            if io_channel.poll():  # the upper layer has submitted new task
                recv_data = io_channel.recv()  # accept new cmd
            else:  # otherwise, continue the loops
                time.sleep(0.1)
                continue
            unpack_task = json.loads(recv_data)

            if unpack_task["cmd"] == "CLOSE-IMM":  # terminated right now!
                logger.info(
                    f"SSHClient({self.remote_host}:{self.remote_port}) stops services."
                )
                break

            assert (
                unpack_task["interactive"] is True
            ), f"Invalid task submitted to the interactive channel({self.remote_host}:{self.remote_port})"

            try:
                modified_cmd = unpack_task["cmd"].strip()
                if modified_cmd[-1] != ";":
                    modified_cmd += ";"
                exe_ret = {"cmd": modified_cmd, "status": True, "out": [], "err": []}

                modified_cmd += " echo EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=`expr 100 + 100`-DONE;"
                # logger.info("cmd = {}".format(modified_cmd))

                self.ssh_client.using_interactive_channel(modified_cmd)
                ret = None
                should_close = False
                while not should_close:
                    while ret is None:
                        time.sleep(0.1)
                        ret = self.ssh_client.querying_interactive_channel()

                    if "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE" in ret:
                        should_close = True
                    if ret is not None:
                        if unpack_task["allow_print"] is True:
                            print(ret, end="")
                    ret = None

            except Exception as e:

                exe_ret["status"] = False
                logger.error(
                    "Error when processing cmd=({}), node=({}:{}) : {}".format(
                        unpack_task["cmd"], self.remote_host, self.remote_port, e
                    )
                )
            finally:
                logger.debug(
                    "In deamon_execution: {}:{} recvs cmd({}) from master".format(
                        self.remote_host, self.remote_port, unpack_task["cmd"]
                    )
                )
                io_channel.send(json.dumps(exe_ret))
                pass
            pass

        pass

    def sftp_file_mode(self, io_channel):
        logger.info(
            f"{self.id}({self.remote_host}:{self.remote_port}) is working in sftp mode"
        )
        self._sftp_service = SFTPService(self.ssh_client)

        task = io_channel.recv()
        try:
            tmp_task = json.loads(task)
            struct_task = json.loads(tmp_task["cmd"])
            assert (
                struct_task["type"] == "SYNC_FOLDER"
            ), "Error of unknown service type {}".format(struct_task["type"])

            self._sftp_service.copy_files(
                source=struct_task["src"], target=struct_task["target"]
            )

            ret_task = {
                "type": struct_task["type"],
                "status": True,
                "src": struct_task["src"],
                "target": struct_task["target"],
            }

            io_channel.send(json.dumps(ret_task))

        except Exception as e:
            logger.error(
                f"Encounter error of processing on node {self.remote_host}, for reason: {e}"
            )

        pass

    def deamon_execution(self, io_channel):
        logger.debug(
            f"Creating deamon_execution for {self.remote_host}:{self.remote_port}"
        )

        is_connected = False

        try:
            self.ssh_client = SshClientImpl(
                self.remote_host,
                self.remote_port,
                self.remote_username,
                self.remote_password,
            )
            is_connected = True
        except Exception as e:
            logger.info(
                f"Cannot connected to {self.remote_host}:{self.remote_port}, for error: {e}"
            )
        finally:
            pass

        if is_connected:
            io_channel.send("CONNECTION_IS_READY")
        else:
            io_channel.send("CONNECTION_IS_FAILED")
            return

        if args.sync:
            self.sftp_file_mode(io_channel)
        else:
            self.task_routing(io_channel)
        # derived API
        # if args.interactive:
        #     self.ssh_remote_execution_interactive(io_channel)
        #     return

        # self.ssh_remote_execution(io_channel)
        pass

    def wait_task_from_master(self, io_channel):
        logger.debug(
            f"{self.remote_host}:{self.remote_port} is ready, wait for tasks from master..."
        )

        if io_channel.poll():  # the upper layer has submitted new task
            recv_data = io_channel.recv()  # accept new cmd
        else:  # otherwise, return None
            time.sleep(0.1)
            return None
        unpack_task = json.loads(recv_data)
        logger.debug(
            f"{self.remote_host}:{self.remote_port} accepts a cmd({unpack_task['cmd']}) from master..."
        )

        return unpack_task

    def task_routing(self, io_channel):
        while True:
            unpack_task = self.wait_task_from_master(io_channel)
            if unpack_task is None:
                continue
            if unpack_task["cmd"] == "CLOSE-IMM":  # terminated right now!
                logger.debug(
                    f"SSHClient({self.remote_host}:{self.remote_port}) stops services."
                )
                break

            modified_cmd = unpack_task["cmd"].strip()
            if modified_cmd[-1] != ";":
                modified_cmd += ";"

            exe_ret = {"cmd": modified_cmd, "status": True, "out": [], "err": []}

            modified_cmd += (
                " echo EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=`expr 100 + 100`-DONE;"
            )

            if unpack_task["interactive"] is True:
                self.execute_async(cmd=modified_cmd, ret=exe_ret)
                pass
            else:
                self.execute_sync(cmd=modified_cmd, ret=exe_ret)
                pass

            io_channel.send(json.dumps(exe_ret))

        pass

    def execute_async(self, cmd: str, ret: dict):
        logger.info(f"{self.remote_host}:{self.remote_port} Executing in async mode")
        try:
            self.ssh_client.using_interactive_channel(cmd)
            ret_ = None
            should_close = False
            while not should_close:
                while ret_ is None:
                    time.sleep(0.1)
                    ret_ = self.ssh_client.querying_interactive_channel()
                if "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE" in ret_:
                    should_close = True
                if ret_ is not None:
                    print(ret_, end="")
                ret_ = None

        except Exception as e:
            ret["status"] = False
            logger.error(
                f"""Error when processing cmd=({ret['cmd']}), """
                f"""node=({self.remote_host}:{self.remote_port}) : {e}"""
            )
        finally:
            logger.debug(
                f"""In deamon_execution: {self.remote_host}:{self.remote_port}"""
                f""" recvs cmd({ret['cmd']}) from master"""
            )
        pass

    def execute_sync(self, cmd: str, ret: dict):
        try:
            ret_ = self.ssh_client.execute(cmd, sudo=False)
            ret["out"] = ret_["out"]
            ret["err"] = ret_["err"]
            ret["status"] = True

            if (
                "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE"
                not in " ".join(ret["out"])
            ) and (
                "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE"
                not in " ".join(ret["err"])
            ):
                ret["status"] = False  # the cmd are not executed correctly

        except Exception as e:
            ret["status"] = False
            logger.error(
                f"Error when processing cmd=({ret['cmd']}), node=({self.remote_host}:{self.remote_port}) : {e}"
            )
        finally:
            pass

        pass

    def connect(self):

        self.process_handler = mp.Process(
            target=self.deamon_execution, args=(self.child_channel,),
        )

        logger.debug(
            f"Really connecting to the remote ({self.remote_host}:{self.remote_port},{self.remote_username},{self.remote_password})..."
        )
        pass

    def start(self):
        logger.debug(f"{self.remote_host}:{self.remote_port} starts services")
        self.process_handler.start()

    def close(self):
        logger.info(
            f"{self.id}({self.remote_host}:{self.remote_port}) closes connection"
        )
        self.process_handler.join()


class ConnectionManager:
    def __init__(self, enable_sftp=False):
        logger.info("Creating ConnectionManager")
        self.ssh_handler = []
        self.enable_sftp = False
        if enable_sftp:
            logger.warning("enable sftp service")
            self.enable_sftp = True
        pass

    def add_client(self, id, ip, port=22, username="newplan", password=" "):
        ssh_client = SSHClientAbst(ip, port, username, password, id)
        self.ssh_handler.append(ssh_client)

    def connect(self):
        for each_ssh in self.ssh_handler:
            each_ssh.connect()

    def query_result_at(self, id="all"):
        is_checked = {}
        execution_with_error = []
        if id == "all":  # query all remotes
            for each_ssh in self.ssh_handler:
                if each_ssh.is_connected:
                    success = each_ssh.query_command("", allowed_print=True)
                    if not success:
                        execution_with_error.append(each_ssh.id)
                else:
                    logger.warning(
                        f"{each_ssh.id}({each_ssh.remote_host}:{each_ssh.remote_port})"
                        "is not connected, ignore."
                    )
        else:  # query some special node
            nodes = [x.strip() for x in id.split(",")]
            success = True
            for each_ssh in self.ssh_handler:

                logger.debug(f"The current id: {each_ssh.id}, expected: {nodes}")

                if each_ssh.is_connected:
                    if each_ssh.id in nodes:
                        success = each_ssh.query_command("", allowed_print=True)
                        is_checked[each_ssh.id] = True
                    else:
                        success = each_ssh.query_command("", allowed_print=False)

                    if not success:
                        execution_with_error.append(each_ssh.id)
                else:
                    logger.warning(
                        f"{each_ssh.id}({each_ssh.remote_host}:{each_ssh.remote_port})"
                        " is not connected, ignore."
                    )

            for each_node in nodes:
                if len(each_node) != 0 and each_node not in is_checked:
                    logger.warning(f"cannot find the associated node({each_node})")
        if len(execution_with_error) != 0:
            logger.warning(f"Some things get wrong at {execution_with_error}")

    def start_service(self):
        for each_ssh in self.ssh_handler:
            each_ssh.start()

        # a barrier to make sure that all connection is ready
        for each_ssh in self.ssh_handler:
            each_ssh.block_until_connected()

    def execute(self, cmd, using_sudo=False, allow_print="", interactive=False):
        for each_ssh in self.ssh_handler:
            each_ssh.send_command(
                command=cmd,
                using_sudo=using_sudo,
                interactive=interactive,
                allow_print=allow_print,
            )
        self.query_result_at(allow_print)

    def stop(self):
        for each_ssh in self.ssh_handler:
            each_ssh.send_command(
                command="CLOSE-IMM",  #
                using_sudo=False,  #
                allow_print="",  #
                interactive=False,  #
            )
        time.sleep(1)

    def close(self):
        for each_ssh in self.ssh_handler:
            each_ssh.close()

    def sync_file(self, src, target, thread_pool=4):
        logger.info("Synching file from {}, to {}".format(src, target))
        if not self.enable_sftp:
            raise Exception("stfp service is not enabled, return immediately")

        data_on_flight = []

        def try_drain_out(data_on_flight, ssh_handler):
            for selected_id in data_on_flight:
                on_flight_ssh = ssh_handler[selected_id]
                ret = on_flight_ssh.get_ret_from_channel()
                if ret is None:  # not executed yet
                    time.sleep(0.01)
                    continue
                else:  # has returned the result
                    assert (
                        ret["status"] is True and ret["type"] == "SYNC_FOLDER"
                    ), f"Failed to sync the folder @ {on_flight_ssh.remote_host}"
                    logger.info(
                        f"{on_flight_ssh.remote_host} has finished the folder synchronization"
                    )
                    data_on_flight.remove(selected_id)
            pass

        for ssh_id in range(0, len(self.ssh_handler)):
            if len(data_on_flight) < thread_pool:  # able to add new task
                active_ssh = self.ssh_handler[ssh_id]
                logger.info(f"Syncing file on node: {active_ssh.remote_host}")
                task = {"type": "SYNC_FOLDER", "src": src, "target": target}
                active_ssh.send_command(
                    command=json.dumps(task),
                    using_sudo=False,
                    interactive=False,
                    allow_print="",
                )
                data_on_flight.append(ssh_id)

            while (
                len(data_on_flight) >= thread_pool
            ):  # break only if there are room to add new task
                try_drain_out(data_on_flight, self.ssh_handler)

        # final drain out all the data on flight with blocking
        while len(data_on_flight) != 0:
            try_drain_out(data_on_flight, self.ssh_handler)

        pass

    def __del__(self):
        logger.info(
            """Finally, it comes to the end, and congraduations, the commands are executed as expected! """
            """Next, it's time to release all the resources and close the connections!"""
        )

        self.stop()
        logger.info("All services are stopped\n\n")

        self.close()
        logger.info("All connections are closed\n\n")


def args_check(args):
    if len(args.cmd) != 0 and args.sync is True:
        raise Exception("You cannot upload file and execute cmd simutately")
    print("Captured the execution cmd is: {}".format(args.cmd))
    pass


def main():
    c_mgr = ConnectionManager(enable_sftp=args.sync)
    for ip_idx in range(0, 16):
        new_ip = "12.12.12." + str(101 + ip_idx)
        server_id = "g" + str(1 + ip_idx)
        c_mgr.add_client(server_id, ip=new_ip)
    logger.info("Adding all client to the master\n\n")
    c_mgr.connect()
    logger.info("After real connect to the remote\n\n")

    c_mgr.start_service()
    time.sleep(1)
    logger.info("All connection are established and start service\n\n")

    if len(args.cmd) != 0:
        c_mgr.execute(
            cmd=args.cmd,
            using_sudo=args.sudo,
            allow_print=args.allow_print,
            interactive=args.interactive,
        )

        logger.info("All Executions are processed\n\n")

    if args.sync:
        c_mgr.sync_file(src=args.sync_path, target=args.sync_path)


if __name__ == "__main__":
    args_check(args)
    main()
