import subprocess
import argparse
import paramiko


try:
    subprocess.check_call(["dpkg-vendor", "--derives-from", "debian"])
    distribution = 'debian'
except:
    distribution = 'centos'

class DiagUtils():
    def __init__(self):
        pass

    def log(self, line, stdout = True):
        self.file.write(line)
        if stdout:
            print(line.rstrip('\n'))

    def log_open(self):
        self.file = open('diag.log', 'w+')

    def log_close(self):
        self.file.close()

    def curl_get(self, ssh, url, parse = False):
        parse_cmd = ''
        if parse:
            parse_cmd = ' | python -mjson.tool'
    
        cmd = 'curl -sS %s' %(url) + parse_cmd
        (stdin, stdout, stderr) = ssh.exec_command(cmd)
        return stdout.readlines()

    def process_check(self, ssh, name):
        cmd = 'ps -C %s -o pid=' %(name)
        (stdin, stdout, stderr) = ssh.exec_command(cmd)
        output = stdout.readline()
        if output:
            self.log('    Process %s, running, PID %s' %(name, output))
            return True
        else:
            self.log('    Process %s, not running\n' %(name))
            return False

diag_utils = DiagUtils()


class DiagConfig():
    def __init__(self, ssh, addr):
        self.ssh = ssh
        self.addr = addr

    def api_server(self):
        diag_utils.log('\nConfiguration API Server\n')
        diag_utils.log('----------------\n')

        diag_utils.log('\nChecking processs...\n')
        if not diag_utils.process_check(self.ssh, 'contrail-api'):
            return

        diag_utils.log('\nChecking API port...\n')
        url = 'http://%s:8082/projects' %(self.addr)
        for line in diag_utils.curl_get(self.ssh, url, parse = True):
            diag_utils.log(line)


    def discovery(self):
        diag_utils.log('\nDiscovery\n')
        diag_utils.log('----------------\n')

        diag_utils.log('\nChecking processs...\n')
        if not diag_utils.process_check(self.ssh, 'contrail-discovery'):
            return

        diag_utils.log('\nChecking registered services/publishers...\n')
        url = 'http://%s:5998/services.json' %(self.addr)
        svc_list = eval(diag_utils.curl_get(self.ssh, url)[0])['services']
        for svc in svc_list:
            diag_utils.log('    %s\n' %(svc['service_type']))
            diag_utils.log('        Address: %s:%s\n' %(svc['info']['ip-address'],
                    svc['info']['port']))
            diag_utils.log('        Status: %s\n' %(svc['status']))
            diag_utils.log('        Admin State: %s\n' %(svc['admin_state']))

        diag_utils.log('\nChecking registered clients/subscribers...\n')
        url = 'http://%s:5998/clients.json' %(self.addr)
        client_list = eval(diag_utils.curl_get(self.ssh, url)[0])['services']
        for client in client_list:
            diag_utils.log('    %s\n' %(client['client_type']))
            diag_utils.log('        Required Service: %s\n' %(client['service_type']))

    def schema(self):
        diag_utils.log('\nSchema Transformer\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'contrail-schema'):
            return

    def svc_monitor(self):
        diag_utils.log('\nService Monitor\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'contrail-svc-monitor'):
            return

    def ifmap(self):
        diag_utils.log('\nIF-MAP Server\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'ifmap-server'):
            return

    def rabbitmq(self):
        diag_utils.log('RabbitMQ\n')
        diag_utils.log('----------------\n')

        cmd = 'rabbitmqctl cluster_status'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        for line in stdout.readlines():
            diag_utils.log(line)

    def node_manager(self):
        #diag_utils.log('Node Manager\n')
        #diag_utils.log('----------------\n')
        pass

    def diag(self):
        diag_utils.log('\n==== Configuration ====\n')
        self.api_server()
        self.discovery()
        self.schema()
        self.svc_monitor()
        self.ifmap()
        self.rabbitmq()
        self.node_manager()


class DiagAnalytics():
    def __init__(self, ssh, addr):
        self.ssh = ssh
        self.addr = addr

    def node_check(self, name):
        diag_utils.log('\nChecking %s...\n' %(name))
        url = 'http://%s:8081/analytics/uves/%s' %(self.addr, name)
        for node in eval(diag_utils.curl_get(self.ssh, url)[0]):
            diag_utils.log('    %s' %(node['name']))
            for line in diag_utils.curl_get(self.ssh, node['href'],
                    parse = True):
                diag_utils.log(line, stdout = False)


    def api_server(self):
        diag_utils.log('\nAnalytics API Server\n')
        diag_utils.log('----------------\n')

        diag_utils.log('\nChecking processs...\n')
        if not diag_utils.process_check(self.ssh, 'contrail-analytics-api'):
            return

        diag_utils.log('\nChecking generators...\n')
        url = 'http://%s:8081/analytics/uves/generators' %(self.addr)
        for generator in eval(diag_utils.curl_get(self.ssh, url)[0]):
            diag_utils.log('    %s\n' %(generator['name']))

        self.node_check('config-nodes')
        self.node_check('analytics-nodes')
        self.node_check('control-nodes')
        self.node_check('vrouters')
        self.node_check('databases')

    def collector(self):
        diag_utils.log('\nCollector\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'contrail-collector'):
            return

    def query_engine(self):
        diag_utils.log('\nQuery Engine\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'contrail-query-engine'):
            return

    def node_manager(self):
        pass

    def diag(self):
        diag_utils.log('\n==== Analytics ====\n')
        self.api_server()
        self.collector()
        self.query_engine()
        self.node_manager()


class DiagControl():
    def __init__(self, ssh, addr):
        self.ssh = ssh
        self.addr = addr

    def control(self):
        diag_utils.log('\nControl\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'contrail-control'):
            return

    def dns(self):
        diag_utils.log('\nDNS\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'dnsd'):
            return

    def named(self):
        diag_utils.log('\nnamed\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'named'):
            return

    def node_manager(self):
        pass

    def diag(self):
        diag_utils.log('\n==== Control ====\n')
        self.control()
        self.dns()
        self.named()
        self.node_manager()


class DiagCompute():
    def __init__(self, ssh, addr):
        self.ssh = ssh
        self.addr = addr

    def vrouter_agent(self):
        diag_utils.log('\nvRouter Agent\n')
        diag_utils.log('----------------\n')

        if not diag_utils.process_check(self.ssh, 'contrail-vrouter-agent'):
            return

    def node_manager(self):
        pass

    def diag(self):
        diag_utils.log('\n==== Compute ====\n')
        self.vrouter_agent()
        self.node_manager()


class DiagDatabase():
    def __init__(self, ssh):
        self.ssh = ssh

    def diag(self):
        diag_utils.log('\n==== Database ====\n')


class DiagNode():

    def __init__(self):
        pass

    def ssh_connect(self, addr, username, password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(addr, username = username, password = password,
                    timeout = 10)
            self.ssh = ssh
        except:
            self.ssh = None

    def node_memory(self):
        diag_utils.log('\nMemory and Process Summary:\n')
        diag_utils.log('----------------\n')
        cmd = 'top -b -n 1 | grep -C 2 "Cpu(s)"'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        for line in stdout.readlines():
            diag_utils.log(line)

    def node_disk(self):
        diag_utils.log('\nDisk Usage Summary:\n')
        diag_utils.log('----------------\n')
        cmd = 'df'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        for line in stdout.readlines():
            diag_utils.log(line)

    def diag(self, addr, username, password):
        role_list = [
                ('contrail-config', DiagConfig),
                #('contrail-database', DiagDatabase),
                ('contrail-analytics', DiagAnalytics),
                ('contrail-control', DiagControl),
                ('dummy', DiagControl),
                ('contrail-vrouter', DiagCompute)]
        diag_utils.log('======== Node %s ========\n' %(addr))
        self.ssh_connect(addr, username, password)
        if not self.ssh:
            diag_utils.log('ERROR: Failed to Connect to %s!\n' %(addr))
            return

        self.node_memory()
        self.node_disk()

        cmd = 'if $(dpkg-vendor --derives-from debian);' + \
              'then echo true;' + \
              'else echo false;' + \
              'fi'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        if stdout.readlines()[0] == 'true\n':
            pkg_cmd = 'dpkg -l '
            for role in role_list:
                (stdin, stdout, stderr) = self.ssh.exec_command(
                        pkg_cmd + role[0])
                if stdout.readline():
                   role[1](self.ssh, addr).diag()
        else:
            pkg_cmd = 'rpm -q '
            for role in role_list:
                (stdin, stdout, stderr) = self.ssh.exec_command(
                        pkg_cmd + role[0])
                if stdout.readline().find('not installed') == -1:
                   role[1](self.ssh, addr).diag()


class DiagShell():

    def __init__(self):
        self.parser_init()

    def parser_init(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--username', help = 'User name')
        parser.add_argument('--password', help = 'Password')
        parser.add_argument('--address',
                metavar = '<IP address>',
                action = 'append',
                help = 'Node')
        self.parser = parser

    def parse(self, argv = None):
        args = self.parser.parse_args(args = argv)
        return args

    def run(self, args):
        node = DiagNode()
        diag_utils.log_open()
        for addr in args.address:
            node.diag(addr, args.username, args.password)
        diag_utils.log_close()

    def main(self):
        args = self.parse()
        self.run(args)


if __name__ == '__main__':
    DiagShell().main()

