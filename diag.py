import subprocess
import argparse
import paramiko


try:
    subprocess.check_call(["dpkg-vendor", "--derives-from", "debian"])
    distribution = 'debian'
except:
    distribution = 'centos'


class DiagConfig():
    def __init__(self, ssh):
        self.ssh = ssh

    def process_check(self, name):
        cmd = 'ps -C %s -o pid=' %(name)
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        output = stdout.readline()
        if output:
            print 'Process %s, running, PID %s' %(name, output)
            return True
        else:
            print 'Process %s, not running' %(name)
            return False

    def api_server(self):
        print '\nConfiguration API Server'
        print '----------------'

        if not self.process_check('contrail-api'):
            return

    def discovery(self):
        print '\nDiscovery'
        print '----------------'

        if not self.process_check('contrail-discovery'):
            return

        cmd = 'curl http://10.84.18.3:5998/services.json'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        services = eval(stdout.readline())['services']
        print 'Services/Publishers:'
        for svc in services:
            print '    %s' %(svc['service_type'])
            print '        Address: %s:%s' %(svc['info']['ip-address'],
                    svc['info']['port'])
            print '        Status: %s' %(svc['status'])
            print '        Admin State: %s' %(svc['admin_state'])

        cmd = 'curl http://10.84.18.3:5998/clients.json'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        clients = eval(stdout.readline())['services']
        print 'Clients/Subscribers:'
        for client in clients:
            print '    %s' %(client['client_type'])
            print '        Required Service: %s' %(client['service_type'])

    def schema(self):
        print '\nSchema Transformer'
        print '----------------'

        if not self.process_check('contrail-schema'):
            return

    def svc_monitor(self):
        print '\nService Monitor'
        print '----------------'

        if not self.process_check('contrail-svc-monitor'):
            return

    def ifmap(self):
        print '\nIF-MAP Server'
        print '----------------'

        if not self.process_check('ifmap-server'):
            return

    def rabbitmq(self):
        print 'RabbitMQ'
        print '----------------'

        cmd = 'rabbitmqctl cluster_status'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        for line in stdout.readlines():
            print line.rstrip('\n')

    def node_manager(self):
        #print 'Node Manager'
        #print '----------------'
        pass

    def diag(self):
        print '\n==== Configuration ===='
        self.api_server()
        self.discovery()
        self.schema()
        self.svc_monitor()
        self.ifmap()
        self.rabbitmq()
        self.node_manager()


class DiagAnalytics():
    def __init__(self, ssh):
        self.ssh = ssh

    def process_check(self, name):
        cmd = 'ps -C %s -o pid=' %(name)
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        output = stdout.readline()
        if output:
            print 'Process %s, running, PID %s' %(name, output)
            return True
        else:
            print 'Process %s, not running' %(name)
            return False

    def api_server(self):
        print '\nAnalytics API Server'
        print '----------------'

        if not self.process_check('contrail-analytics-api'):
            return

    def collector(self):
        print '\nCollector'
        print '----------------'

        if not self.process_check('contrail-collector'):
            return

    def query_engine(self):
        print '\nQuery Engine'
        print '----------------'

        if not self.process_check('contrail-query-engine'):
            return

    def node_manager(self):
        pass

    def diag(self):
        print '\n==== Analytics ===='
        self.api_server()
        self.collector()
        self.query_engine()
        self.node_manager()


class DiagControl():
    def __init__(self, ssh):
        self.ssh = ssh

    def process_check(self, name):
        cmd = 'ps -C %s -o pid=' %(name)
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        output = stdout.readline()
        if output:
            print 'Process %s, running, PID %s' %(name, output)
            return True
        else:
            print 'Process %s, not running' %(name)
            return False

    def control(self):
        print '\nControl'
        print '----------------'

        if not self.process_check('contrail-control'):
            return

    def dns(self):
        print '\nDNS'
        print '----------------'

        if not self.process_check('dnsd'):
            return

    def named(self):
        print '\nnamed'
        print '----------------'

        if not self.process_check('named'):
            return

    def node_manager(self):
        pass

    def diag(self):
        print '\n==== Control ===='
        self.control()
        self.dns()
        self.named()
        self.node_manager()


class DiagCompute():
    def __init__(self, ssh):
        self.ssh = ssh

    def process_check(self, name):
        cmd = 'ps -C %s -o pid=' %(name)
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        output = stdout.readline()
        if output:
            print 'Process %s, running, PID %s' %(name, output)
            return True
        else:
            print 'Process %s, not running' %(name)
            return False

    def vrouter_agent(self):
        print '\nvRouter Agent'
        print '----------------'

        if not self.process_check('contrail-vrouter-agent'):
            return

    def node_manager(self):
        pass

    def diag(self):
        print '\n==== Compute ===='
        self.vrouter_agent()
        self.node_manager()


class DiagDatabase():
    def __init__(self, ssh):
        self.ssh = ssh

    def diag(self):
        print '\n==== Database ===='


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
        print '\nMemory and Process Summary:'
        print '----------------'
        cmd = 'top -b -n 1 | grep -C 2 "Cpu(s)"'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        for line in stdout.readlines():
            print line.rstrip('\n')

    def node_disk(self):
        print '\nDisk Usage Summary:'
        print '----------------'
        cmd = 'df'
        (stdin, stdout, stderr) = self.ssh.exec_command(cmd)
        for line in stdout.readlines():
            print line.rstrip('\n')

    def diag(self, addr, username, password):
        role_list = [
                ('contrail-config', DiagConfig),
                #('contrail-database', DiagDatabase),
                ('contrail-analytics', DiagAnalytics),
                ('contrail-control', DiagControl),
                ('dummy', DiagControl),
                ('contrail-vrouter', DiagCompute)]
        print '======== Node %s ========' %(addr)
        self.ssh_connect(addr, username, password)
        if not self.ssh:
            print 'ERROR: Failed to Connect to %s!' %(addr)
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
                   role[1](self.ssh).diag()
        else:
            pkg_cmd = 'rpm -q '
            for role in role_list:
                (stdin, stdout, stderr) = self.ssh.exec_command(
                        pkg_cmd + role[0])
                if stdout.readline().find('not installed') == -1:
                   role[1](self.ssh).diag()


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
        for addr in args.address:
            node.diag(addr, args.username, args.password)

    def main(self):
        args = self.parse()
        self.run(args)


if __name__ == '__main__':
    DiagShell().main()

