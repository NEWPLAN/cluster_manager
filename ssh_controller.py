#! /usr/bin/env python3


import multiprocessing as mp

import time
import os
import argparse
import datetime
import inspect
import sys

import json
import socket

import traceback

try:
    import paramiko
except ImportError:
    os.system("pip3 install paramiko")
    import paramiko

try:
    import netifaces as nf
except ImportError:
    os.system("pip3 install netifaces")
    import netifaces as nf


class IPAddrHelper(object):
    @staticmethod
    def ipv4_addresses():
        ip_list = []
        for interface in nf.interfaces():
            for link in nf.ifaddresses(interface).get(nf.AF_INET, ()):
                ip_list.append(link["addr"])
        return ip_list

    @staticmethod
    def ipv6_addresses():
        ip_list = []
        for interface in nf.interfaces():
            for link in nf.ifaddresses(interface).get(nf.AF_INET6, ()):
                ip_list.append(link["addr"])
        return ip_list

    @staticmethod
    def simple_ipv6_addresses():
        ip_addrs = IPAddrHelper.ipv6_addresses()
        ret_data = []
        for ip_str in ip_addrs:
            ret_data.append(ip_str.split("%")[0])
            pass
        return ret_data
        pass

    @staticmethod
    def is_local(ip):
        ip_from_dns = IPAddrHelper.query_ip_from_dns(ip)
        local_ip_addr = IPAddrHelper.ipv4_addresses() + IPAddrHelper.ipv6_addresses()
        for ip_addr in ip_from_dns:
            if ip_addr in local_ip_addr:
                return True

        return False
        return ip in IPAddrHelper.ipv4_addresses() + IPAddrHelper.ipv6_addresses()

    @staticmethod
    def query_ip_from_dns(hostname: str):
        ip_list = [hostname]

        def load_ipaddr_helper(net_proto):
            tmp_list = []
            try:
                ipv_addr = socket.getaddrinfo(hostname, None, net_proto)
                for each_elem in ipv_addr:
                    real_ip = each_elem[4][0]
                    tmp_list.append(real_ip)
            except Exception as e:
                print(
                    "failed get ip address, with err={}, stack={}".format(
                        e, traceback.print_exc()
                    ),
                    file=sys.stderr,
                    flush=True,
                )
            return tmp_list

        ip_list += load_ipaddr_helper(socket.AF_INET)
        ip_list += load_ipaddr_helper(socket.AF_INET6)

        ip_list = [x for x in set(ip_list) if x is not None and len(x) != 0]
        return ip_list
        pass


# ip_str = [
#     "bps-node-14",
#     "bps-node-15",
#     "github.com",
#     "",
#     "localhost",
#     "127.0.0.1",
#     "::ffff:157.245.159.242",
#     "fdbd:dc02:2a:716::17",
#     "fdbd:dc02:2a:10e::28",
# ]
# for host_name in ip_str:
#     print(
#         "The target of {} is {}".format(
#             host_name, IPAddrHelper.query_ip_from_dns(host_name)
#         )
#     )
#     print(
#         "The target of {} is local = {}".format(
#             host_name, IPAddrHelper.is_local(host_name)
#         )
#     )

# exit(-1)


class ArgHelper(object):
    @staticmethod
    def load_arguments():
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument("--H", type=str, help="host ID [1,2,3,4,5]")
        parser.add_argument(
            "--cmd", type=str, default="", help="executing your command"
        )
        parser.add_argument(
            "--sync", action="store_true", help="Sync data between local to remote"
        )
        parser.add_argument(
            "--sync_path", type=str, default="", help="The source file path to sync"
        )
        parser.add_argument(
            "--sudo", action="store_true", help="working under sudo mode"
        )
        parser.add_argument(
            "--user", type=str, default="newplan", help="username for ssh"
        )
        parser.add_argument(
            "--passwd", type=str, default=" ", help="password to login remote machine"
        )
        parser.add_argument(
            "--port", type=int, default=22, help="the port of ssh service"
        )
        parser.add_argument(
            "--host", type=str, default="", help="the host ip for this session"
        )
        parser.add_argument(
            "--allow_print",
            type=str,
            default="",
            help="the node to display the ret, split by ',' or all to show all the node ",
        )

        parser.add_argument(
            "--stream_log",
            action="store_true",
            default=False,
            help="get streamed logs from remote sessions",
        )

        parser.add_argument(
            "--interactive",
            action="store_true",
            default=False,
            help="working under interactive mode",
        )

        parser.add_argument(
            "--use_glog",
            action="store_true",
            default=True,
            help="enable glog as logger or not",
        )
        parser.add_argument(
            "--env",
            type=str,
            default="",
            help="speficy the environment for execution, multiple envs are split by ';'",
        )

        parser.add_argument(
            "--set_env",
            type=str,
            default=None,
            help="put local environment variables to remote, split by','."
            ' for example: --set_env="PATH,LIBRARY_PATH"',
        )

        parser.add_argument(
            "--enable_full_log",
            action="store_true",
            help="enable full log for other module",
        )

        parser.add_argument(
            "--log_level",
            type=str,
            default="info",
            help="log level for print result,"
            " the valid values are must in "
            "[info, debug, warning, error],"
            " and  are case insensitive",
        )

        parser.add_argument(
            "--key",
            type=str,
            default="",
            help="Key to log remote session for ssh, instead of using passward",
        )

        parser.add_argument(
            "--dump_args",
            action="store_true",
            default=True,
            help="dump arguments for this session, only work for debug model",
        )

        parser.add_argument(
            "--dump_log",
            action="store_true",
            default=False,
            help="dump output logs for remote session, including stdout and stderr",
        )

        parser.add_argument(
            "--log_path",
            type=str,
            default="",
            help="dump output logs for remote session, including stdout and stderr",
        )

        parser.add_argument(
            "--log_individual",
            action="store_true",
            default=False,
            help="log individual for prefix",
        )

        parser.add_argument(
            "--debug_shell",
            action="store_true",
            default=False,
            help="show the execution of shell commands in remote session for debug",
        )

        return parser.parse_args()


args = ArgHelper.load_arguments()


class ResourceHelper(object):
    @staticmethod
    def is_valid(path: str, check_exist=True, check_file=False, check_directory=False):
        pass_check = True
        if pass_check and check_exist:
            if not os.path.exists(path):
                logger.warning(
                    "check is valid for {} failed, not existing".format(path)
                )
                pass_check = False

        if pass_check and check_file:
            if not os.path.isfile(path):
                logger.warning("check is valid for {} failed, not a file".format(path))
                pass_check = False

        if pass_check and check_directory:
            if not os.path.isdir(path):
                logger.warning(
                    "check is valid for {} failed, not a directory".format(path)
                )
                pass_check = False

        return pass_check

    @staticmethod
    def check_or_die(
        path: str, check_exist=True, check_file=False, check_directory=False
    ):
        if not ResourceHelper.is_valid(path, check_exist, check_file, check_directory):
            logger.fatal(
                "Failed to check for: path={}, check_exist={}, check_file={},check_directory={}".format(
                    path, check_exist, check_file, check_directory
                )
            )
        pass

    @staticmethod
    def str_time_now():
        now = int(round(time.time() * 1000))
        now02 = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(now / 1000))
        return now02


def load_logger(args):
    def get_buildin_loger():
        import logging

        log_level = None
        log_level_str = args.log_level.upper()
        if log_level_str == "INFO":
            log_level = logging.INFO
        elif log_level_str == "DEBUG":
            log_level = logging.DEBUG
        elif log_level_str == "WARNING":
            log_level = logging.WARNING
        elif log_level_str == "ERROR":
            log_level = logging.ERROR
        else:
            assert log_level_str in (
                "INFO",
                "DEBUG",
                "WARNING",
                "ERROR",
            ), 'Invalid log level: {}, must be in ["INFO", "DEBUG", "WARNING", "ERROR"]'.format(
                log_level
            )
        print(
            "[INIT: {} {}:{}] \tSeting log level to: {}".format(
                datetime.datetime.now(),
                __file__,
                inspect.currentframe().f_lineno,
                log_level_str,
            ),
            flush=True,
        )

        logging.basicConfig(
            level=log_level,
            format="[%(levelname)s: %(asctime)s %(filename)s:%(lineno)d] \t%(message)s",
        )
        # format='[%(levelname)s: %(asctime)s %(thread)d %(funcName)s %(filename)s:%(lineno)d] \t%(message)s'
        logger = logging.getLogger(__name__)
        return logger

    def get_glog():
        import glog as logger

        return logger

    if args.use_glog:
        try:
            logger = get_glog()
        except ImportError as e:
            args.use_glog = False
            logger = get_buildin_loger()
            pass
    else:
        logger = get_buildin_loger()

    if not args.enable_full_log and not args.use_glog:
        from importlib import reload
        import logging

        logging.shutdown()
        reload(logging)
        pass
    return logger


logger = load_logger(args)


class SshClientImpl:
    "A wrapper of paramiko.SSHClient"
    TIMEOUT = 4  # by default, the maximum time to wait for an ssh connection is 4s

    def __del__(
        self,
    ):
        if self._fp_handler_ is not None:
            self._fp_handler_.close()
        if self._pipelined_channel is not None:
            self._pipelined_channel.close()
        if self._ssh_interactive is not None:
            self._ssh_interactive.close()
        self.client.close()

    def __init__(
        self,
        host,
        port,
        username,
        password=None,
        key=None,
        passphrase=None,
        rsa_pub=None,
        log_file_name=None,
    ):
        self.username = username
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = host
        self.port = port
        self._ssh_interactive = None
        self._pipelined_channel = None
        self._cached_bytes_ = b""
        p_key = key
        self.log_file_name = log_file_name
        self._fp_handler_ = None

        # ref: https://blog.csdn.net/DaMercy/article/details/127780178
        if rsa_pub != None:  # rsa_pub = "~/.ssh/id_rsa"
            logger.debug("Using public RSA key to loggin remote")
            ResourceHelper.check_or_die(path=rsa_pub)
            p_key = paramiko.RSAKey.from_private_key_file(rsa_pub, password=None)
            self.client.connect(
                host,
                port,
                username=username,
                password=password,
                pkey=p_key,
                timeout=self.TIMEOUT,
            )

        else:
            self.client.connect(
                host,
                port,
                username=username,
                password=password,
                pkey=key,
                timeout=self.TIMEOUT,
            )

    def using_interactive_channel(self, cmd):
        # ref: https://blog.csdn.net/weixin_39912556/article/details/80587180
        # ref: https://blog.csdn.net/qq_31127143/article/details/124707117
        if self._ssh_interactive is None:
            self._ssh_interactive = self.client.invoke_shell()
            # self._ssh_interactive.set_combine_stderr(True)
            # self._ssh_interactive.settimeout(90)
            self._ssh_interactive.settimeout(0.0)
        try:
            self._ssh_interactive.send(cmd + "\r")
            # self._ssh_interactive.send('echo EXECUTION-STATUS:"$?"\r')
        except Exception as e:
            logger.error(
                f"Error of executing {cmd}, error: {e}, stack: {traceback.print_exc()}"
            )

    def use_streamed_channel(self, cmd):
        # non_blocking mode: https://gist.github.com/kdheepak/c18f030494fea16ffd92d95c93a6d40d
        # https://stackoverflow.com/questions/760978/long-running-ssh-commands-in-python-paramiko-module-and-how-to-end-them

        if self._pipelined_channel is None:
            self._pipelined_channel = self.client.get_transport().open_session()
            # self._pipelined_channel.settimeout(0.0)
            self._pipelined_channel.set_combine_stderr(True)
            # self._pipelined_channel.get_pty()
        try:
            self._pipelined_channel.exec_command(cmd)
            pass
        except Exception as e:
            logger.error(
                f"Error of executing {cmd}, error: {e}, stack: {traceback.print_exc()}"
            )
        pass

    def dump_log(self, data_utf8):
        if args.dump_log == False:
            return

        if data_utf8 is None or len(data_utf8) == 0:
            return

        if self._fp_handler_ is None:
            if len(args.log_path) == 0:
                logger.fatal("No log file specified")
                raise ValueError("No log file specified in --log_path")

            if (
                args.log_individual is True
                and len(args.log_prefix) != 0
                and len(args.log_path) != 0
            ):
                args.unqiue_log_path = os.path.join(args.log_path, args.log_prefix)
            else:
                args.unqiue_log_path = args.log_path

            if not os.path.exists(args.unqiue_log_path):
                os.makedirs(name=args.unqiue_log_path, mode=0o777, exist_ok=True)

            real_log_path = os.path.join(args.unqiue_log_path, self.log_file_name)

            self._fp_handler_ = open(real_log_path + ".txt", "bw")
            pass
        self._fp_handler_.write(data_utf8)
        self._fp_handler_.flush()

    def __read_helper__(self, channel, repeat=10, read_byte=4096):
        cnt = 0
        while not channel.recv_ready():
            time.sleep(0.1)
            cnt += 1
            if cnt > repeat:
                return None
            pass

        try:
            read_data = channel.recv(read_byte)
            self._cached_bytes_ += read_data

            self.dump_log(read_data)

            ret_str = self._cached_bytes_.decode("utf-8")

            self._cached_bytes_ = b""  # only clean result when decode success
            # ret_str = channel.recv(read_byte).decode("utf-8")
            prefix_format = "<{}>:   ".format(self.host)
            joint_prefix = "\n" + " " * len(prefix_format)
            split_tmp_result = ret_str.split("\n")
            ret_str = (
                prefix_format
                + joint_prefix.join(split_tmp_result[:-1])
                + "\n"
                + split_tmp_result[-1]  # for last one, we should alway keep the \n
            )
            return ret_str
        except UnicodeDecodeError as e:
            logger.warning(
                f"node({self.host}:{self.port}) decode error, will cache it and redecode it again"
                f", for reason: {e}, the stack:{traceback.print_exc()}"
            )
            return None

        pass

    def query_streamed_channel(self):  # not finished yet
        assert self._pipelined_channel is not None, (
            "Invalid ssh interactive channel, "
            "please using 'using_streamed_channel' "
            f"to submit the command to {self.host}:{self.port}"
        )

        execution_status = None
        if self._pipelined_channel.exit_status_ready():
            execution_status = self._pipelined_channel.recv_exit_status()

        result = self.__read_helper__(self._pipelined_channel)

        if result is not None:
            return result, None

        last_bytes = []
        if self._pipelined_channel.exit_status_ready():
            while True:
                new_data = self.__read_helper__(self._pipelined_channel)
                if new_data is not None:
                    last_bytes.append(new_data)
                else:
                    break

        ret = None if len(last_bytes) == 0 else "".join(last_bytes)
        return ret, execution_status
        pass

    def querying_interactive_channel(self):
        assert self._ssh_interactive is not None, (
            "Invalid ssh interactive channel, "
            "please using 'using_interactive_channel' "
            f"to submit the command to {self.host}:{self.port}"
        )

        cnt = 0
        while not self._ssh_interactive.recv_ready():
            time.sleep(0.2)
            cnt += 1
            if cnt > 10:
                return None

        try:
            ret_str = self._ssh_interactive.recv(16384).decode("utf-8")

            prefix_format = "<{}>:   ".format(self.host)
            joint_prefix = "\n" + " " * len(prefix_format)
            split_tmp_result = ret_str.split("\n")
            ret_str = (
                prefix_format
                + joint_prefix.join(split_tmp_result[:-1])
                + "\n"
                + split_tmp_result[-1]  # for last one, we should alway keep the \n
            )

        except Exception as e:
            logger.error(
                f"node({self.host}:{self.port}) unknown error for execution"
                f", for reason: {e}, stack: {traceback.print_exc()}"
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

    def _load_env_helper_(self, env):
        env_prefix = ""
        if env is None:
            return env_prefix

        env = env.strip()
        if len(env) == 0:
            return [env_prefix for x in range(5)]  # return immediately if error

        while len(env) > 0 and env[-1] == ";":
            env = env[:-2]

        while len(env) > 0 and env[-1] == "/":
            env = env[:-2]

        BASE_PREFIX = env

        cpp_include_path = f"{BASE_PREFIX}/include:"
        c_include_path = f"{BASE_PREFIX}/include:"
        path = f"{BASE_PREFIX}/bin:"
        ld_library_path = f"{BASE_PREFIX}/lib:{BASE_PREFIX}/lib64:"
        library_path = f"{BASE_PREFIX}/lib:{BASE_PREFIX}/lib64:"

        return path, c_include_path, cpp_include_path, ld_library_path, library_path

    def load_env(self, env=args.env):
        env_prefix = " set -e; "

        env_vect = env.split(";")
        env_str: dict[list] = {
            "path": [],
            "c_include_path": [],
            "cpp_include_path": [],
            "ld_library_path": [],
            "library_path": [],
        }
        for each_env in env_vect:
            (
                path,
                c_include_path,
                cpp_include_path,
                ld_library_path,
                library_path,
            ) = self._load_env_helper_(each_env)
            env_str["path"].append(path)
            env_str["c_include_path"].append(c_include_path)
            env_str["cpp_include_path"].append(cpp_include_path)
            env_str["ld_library_path"].append(ld_library_path)
            env_str["library_path"].append(library_path)

        ret_env_var = ""
        ret_env_var += " export PATH={}:$PATH;".format("".join(env_str["path"]))
        ret_env_var += " export C_INCLUDE_PATH={}:$C_INCLUDE_PATH;".format(
            "".join(env_str["c_include_path"])
        )
        ret_env_var += " export CPLUS_INCLUDE_PATH={}:$CPLUS_INCLUDE_PATH;".format(
            "".join(env_str["cpp_include_path"])
        )
        ret_env_var += " export LD_LIBRARY_PATH={}:$LD_LIBRARY_PATH;".format(
            "".join(env_str["ld_library_path"])
        )
        ret_env_var += " export LIBRARY_PATH={}:$LIBRARY_PATH;".format(
            "".join(env_str["library_path"])
        )
        return ret_env_var + env_prefix

    def execute(self, command, sudo=False):
        feed_password = False

        if args.sudo:
            logger.warning("WARNING: execute with sudo")
            command = "sudo -S -p '' %s" % command
            feed_password = True

        real_execute_cmd = self.load_env() + command

        logger.debug(
            "[{}:{}] Real execution cmd: {}".format(
                self.host, self.port, real_execute_cmd
            )
        )

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
        """Uploads the contents of the source directory to the target path. The
        target directory needs to exists. All subdirectories in source are
        created under target.
        """

        if source == target and IPAddrHelper.is_local(self.borrowed_ctx.host):
            logger.warning("IGNORE self-node: {}".format(self.borrowed_ctx.host))
            return

        item_name = None

        try:
            if os.path.isdir(source):  # create directory if it is
                self.mkdir(target, ignore_existing=True)

            for item in os.listdir(source):
                if os.path.isfile(os.path.join(source, item)):
                    logger.debug(
                        "processing {} --> {}".format(
                            os.path.join(source, item), self.borrowed_ctx.host
                        )
                    )
                    item_name = item
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
                "Error of processing copy {}/{} to {}/{} in target = ({}:{}), for reason: {}, stack: {}".format(
                    source,
                    item_name,
                    target,
                    item_name,
                    self.borrowed_ctx.host,
                    self.borrowed_ctx.port,
                    e,
                    traceback.print_exc(),
                )
            )
            exit(0)

    def mkdir(self, path, mode=1776, ignore_existing=False):
        """Augments mkdir by adding an option to not fail if the folder exists"""
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


class SSHClientSession:
    def __init__(self, host, port, username, password, id):
        self.remote_host = host
        self.remote_port = port
        self.remote_username = username
        self.remote_password = password
        self.id = id
        self.node_idx = -1

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
                    time.sleep(0.5)

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

        if args.interactive == True:
            allowed_print = False

        if ret["status"] is False:  # encounting errors
            logger.error("Encounter an error at {}".format(self.id))
            allowed_print = True
            encounting_error = True

        if allowed_print or encounting_error:
            logger.warning(
                "The result of execution cmd ({}) from {}({}:{}) is:\n{}".format(
                    ret["cmd"],
                    self.id,
                    self.remote_host,
                    self.remote_port,
                    " ".join(ret["out"]).replace(
                        "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE\r\n", ""
                    )
                    + " ".join(ret["err"]).replace(
                        "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE\r\n", ""
                    ),
                )
            )

        return ret["status"] is True

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
                f"Encounter error of processing on node {self.remote_host}, for reason: {e}, stack: {traceback.print_exc()}"
            )

        pass

    def deamon_execution(self, io_channel):
        logger.debug(
            f"Creating deamon_execution for {self.remote_host}:{self.remote_port}"
        )

        is_connected = False

        try:
            self.ssh_client = SshClientImpl(
                host=self.remote_host,
                port=self.remote_port,
                username=self.remote_username,
                password=self.remote_password,
                rsa_pub=args.key if len(args.key) != 0 else None,
                log_file_name=self.id + "." + str(self.node_idx),
            )
            is_connected = True
        except Exception as e:
            logger.error(
                f"Cannot connected to {self.remote_host}:{self.remote_port}, for error: {e}, stack: {traceback.print_exc()}"
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

        pass

    def wait_task_from_master(self, io_channel):
        logger.debug(
            f"{self.remote_host}:{self.remote_port} is ready, wait for tasks from master..."
        )

        if io_channel.poll():  # the upper layer has submitted new task
            recv_data = io_channel.recv()  # accept new cmd
        else:  # otherwise, return None
            time.sleep(0.5)
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
            debug_shell_cmd = "set -ex ;" if args.debug_shell else "set -e ;"
            prefix_cmd = "export UNIQUE_SERVER_NODE_IDX={}; ".format(self.node_idx)
            postfix_cmd = "  wait && echo EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=`expr 100 + 100`-DONE;"

            modified_cmd = unpack_task["cmd"].strip()
            if modified_cmd[-1] != ";":
                modified_cmd += ";"

            exe_ret = {"cmd": modified_cmd, "status": True, "out": [], "err": []}

            remote_cmd = " ".join(
                [
                    debug_shell_cmd,
                    prefix_cmd,
                    modified_cmd,
                    postfix_cmd,
                ]
            )

            if unpack_task["interactive"] is True:
                self.execute_async(cmd=remote_cmd, ret=exe_ret)
                pass
            else:
                self.execute_sync(cmd=remote_cmd, ret=exe_ret)
                pass

            io_channel.send(json.dumps(exe_ret))

        pass

    def execute_async(self, cmd: str, ret: dict):
        logger.info(
            "[{}:{}] Executing [{}] in async mode".format(
                self.remote_host, self.remote_port, self.ssh_client.load_env() + cmd
            )
        )
        try:
            if args.stream_log:
                self.ssh_client.use_streamed_channel(self.ssh_client.load_env() + cmd)
            else:
                self.ssh_client.using_interactive_channel(
                    self.ssh_client.load_env() + cmd
                )

            ret_ = None
            should_close = False
            while not should_close:
                while ret_ is None:
                    logger.debug("pull result right now")
                    time.sleep(0.2)
                    if args.stream_log:
                        ret_, ret_code = self.ssh_client.query_streamed_channel()
                        logger.debug("ret-code: {}".format(ret_code))

                        if ret_code is not None:
                            ret["status"] = True if ret_code == 0 else False
                            should_close = True
                            break

                    else:
                        ret_ = self.ssh_client.querying_interactive_channel()

                if (
                    ret_ is not None
                    and "EVERYTHING_IS_TERMINATED_CORRECTLY_WITH=200-DONE" in ret_
                ):
                    should_close = True

                if ret_ is not None:
                    print(ret_, end="", flush=True)
                ret_ = None

        except Exception as e:
            ret["status"] = False
            logger.error(
                f"""Error when processing cmd=({ret['cmd']}), """
                f"""node=({self.remote_host}:{self.remote_port}) for reson: {e}, stack: {traceback.print_exc()}"""
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
                f"Error when processing cmd=({ret['cmd']}), node=({self.remote_host}:{self.remote_port}) for reason: {e}, stack: {traceback.print_exc()}"
            )
        finally:
            pass

        pass

    def connect(self):
        self.process_handler = mp.Process(
            target=self.deamon_execution,
            args=(self.child_channel,),
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
        self.ssh_count_start = 0
        if enable_sftp:
            logger.warning("enable sftp service")
            self.enable_sftp = True
        pass

    def allocate_node_id(self):
        ret = self.ssh_count_start
        self.ssh_count_start += 1
        return ret

    def add_client(self, id, ip, port=22, username="newplan", password=" "):
        ssh_client_sess = SSHClientSession(ip, port, username, password, id)
        ssh_client_sess.node_idx = self.allocate_node_id()
        self.ssh_handler.append(ssh_client_sess)

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
            logger.warning(
                f"\033[33mSome things get wrong at {execution_with_error}\033[0m"
            )

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
                    time.sleep(0.5)
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
    logger.info("Captured the execution cmd is: {}".format(args.cmd))
    pass


def pre_processing():
    args_check(args)

    run_mode = 0

    if args.dump_args is True:
        logger.debug("dumped argument for this launcher: {}".format(args))

    if args.sync is True:  # sync file
        run_mode += 1
        pass
    if len(args.cmd) != 0:  # use bash to execute cmd
        run_mode += 1
        pass

    if args.stream_log is True:
        args.interactive = True

    if args.log_individual is True:
        args.log_prefix = ResourceHelper.str_time_now()

    assert (
        run_mode != 2 and run_mode != 0
    ), "you cannot run both sync file and execute cmd simultaneously, or put them empty simultaneously"

    if len(args.host) != 0:
        args.host_vect = args.host.split(",")
        logger.debug("get {} host(s): {}".format(len(args.host_vect), args.host_vect))

    c_mgr = ConnectionManager(enable_sftp=args.sync)
    for remote_host in args.host_vect:
        c_mgr.add_client(
            id=remote_host, ip=remote_host, port=args.port, username=args.user
        )
        pass

    logger.info("Adding all client to the master\n\n")
    c_mgr.connect()
    logger.info("After real connect to the remote\n\n")

    c_mgr.start_service()
    time.sleep(1)
    logger.info("All connection are established and start service\n\n")

    return c_mgr


def main():
    c_mgr = pre_processing()

    if len(args.cmd) != 0:
        c_mgr.execute(
            cmd=args.cmd,
            using_sudo=args.sudo,
            allow_print=args.allow_print,
            interactive=args.interactive,
        )

        log_prefix = "============================"

        logger.info(
            " ".join(
                [
                    log_prefix,
                    "All executions are processed successfully, now release resources",
                    log_prefix,
                    "\n\n",
                ]
            )
        )

    if args.sync:
        c_mgr.sync_file(src=args.sync_path, target=args.sync_path)


if __name__ == "__main__":
    main()
