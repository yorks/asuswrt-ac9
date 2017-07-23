/*
 
   shadowvpn (server & client ) start stop 

*/

#include <rc.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <string.h>
#include <time.h>

#define BUF_SIZE 256
#define CONFIG_DIR "/etc/shadowvpn"
#define SAVE_DIR "/jffs/shadowvpn"


void set_cf2nvram(const char *name, const char *path)
{
    FILE *fp=NULL;
    char buf[200];

    fp=fopen(path, "ro");
    if(fp == NULL) return;
    while(fgets(buf, sizeof(buf), fp)){
        if(strncmp(buf, "#", 1) == 0) continue;
        if(strchr(buf, '=') == NULL) continue;
        char key[32];
        char value[100];
        sscanf(buf, "%[^=]=%[^#\n ]", key, value);
        char nvname[32];
        sprintf(nvname, "shadowvpn_%s_%s", name, key);
        nvram_set(nvname, value); 
       //printf("%s=%s\n", key, value);
    }
    if(NULL!=fp) fclose(fp);
    fp = NULL;
    nvram_commit();
    logmessage("shadowvpn", "save cf %s to nvram done.", path );
}

void write_up_down_script(const char *name, const char *up_or_down)
{
    FILE *fp=NULL;
    char buf[BUF_SIZE];
    char path[PATH_MAX];
    mkdir(CONFIG_DIR, 0700);

    sprintf(path, "%s/%s-%s.sh",CONFIG_DIR, name, up_or_down);

    fp=fopen(path, "w");
    if (fp==NULL){
	logmessage("shadowvpn", "wirte script failed when open:");
	logmessage("shadowvpn", path);
	return ;
    }

    sprintf(&buf[0], "shadowvpn_%s_%s_content", name, up_or_down);
    if( nvram_get(&buf[0]) ){
         fprintf(fp, "#!/bin/sh\n\n%s", nvram_safe_get(&buf[0]));
    }else{
         if(strcmp(up_or_down, "down") == 0){
             fprintf(fp, "#!/bin/sh\n\n" );
             fprintf(fp, "iptables -t nat -D POSTROUTING -o $intf -j MASQUERADE\n" );
             fprintf(fp, "iptables -D FORWARD -i $intf -m state --state RELATED,ESTABLISHED -j ACCEPT\n" );
             fprintf(fp, "iptables -D FORWARD -o $intf -j ACCEPT\n" );

         }else{
             fprintf(fp, "#!/bin/sh\n\n");
             fprintf(fp, "ip addr add $net dev $intf\n");
             fprintf(fp, "ip link set $intf mtu $mtu\n");
             fprintf(fp, "ip link set $intf up\n");
             fprintf(fp, "echo 0 > /proc/sys/net/ipv4/conf/$intf/rp_filter\n");
             fprintf(fp, "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter\n");
             fprintf(fp, "for m in ip_set ip_set_hash_ip xt_set; do modprobe $m;done\n");
             fprintf(fp, "iptables -t nat -A POSTROUTING -o $intf -j MASQUERADE\n");
             fprintf(fp, "iptables -I FORWARD 1 -i $intf -m state --state RELATED,ESTABLISHED -j ACCEPT\n");
             fprintf(fp, "iptables -I FORWARD 1 -o $intf -j ACCEPT\n");
             fprintf(fp, "ip route add $server via $(ip route show 0/0 | awk '{print $3}')\n");
             fprintf(fp, "ip r add default dev $intf table vpn\n");
             fprintf(fp, "ip rule add fwmark 200 table vpn\n");
             fprintf(fp, "ipset  list vpnlist | grep -q vpnlist || ipset create vpnlist iphash\n");
             fprintf(fp, "iptables -t mangle -L PREROUTING  -n  | grep -q vpnfwmark || { iptables -t mangle -N vpnfwmark; iptables -t mangle -A PREROUTING -j vpnfwmark ; }\n");
             fprintf(fp, "iptables -t mangle -L OUTPUT  -n  | grep -q vpnfwmark || iptables -t mangle -A OUTPUT -j vpnfwmark\n");
             fprintf(fp, "iptables -t mangle -L vpnfwmark | grep -q 0xc8 || iptables -t mangle -A vpnfwmark -m set --match-set vpnlist dst -j MARK --set-mark 200\n");
             fprintf(fp, "iptables -t nat -L POSTROUTING | grep -q 0xc8  || iptables -t nat -A POSTROUTING -m mark --mark 200 -j MASQUERADE\n");
         }
    }

    if(NULL!=fp) fclose(fp);
    fp = NULL;
        
    
    sprintf(&buf[0], "%s/%s_%s.sh", SAVE_DIR, name, up_or_down);
    if ( check_if_file_exist(&buf[0]) ){
        eval("cp", "-f", &buf[0], path);
    }
    eval("chmod", "+x",  path);
    
}
void write_shadowvpn_conf(const char *name)
{
        FILE *fp=NULL;
	char buffer[BUF_SIZE];
	char config_name[64];
	char config_path[PATH_MAX];
	char up_path[PATH_MAX];
	char down_path[PATH_MAX];
	mkdir(CONFIG_DIR, 0700);

	sprintf(config_name, "%s.conf", name);
	sprintf(config_path, "%s/%s", CONFIG_DIR, config_name);

	sprintf(up_path, "%s/%s-up.sh",CONFIG_DIR, name);
	sprintf(down_path, "%s/%s-down.sh", CONFIG_DIR, name);

        /* write up down script */
        write_up_down_script(name, "up"); 
        write_up_down_script(name, "down"); 

        /* write /etc/shadowvpn-%s.conf */
        logmessage("shadowvpn", "writing config");
        fp=fopen(config_path, "w");
        if (fp==NULL) return;

	sprintf(&buffer[0], "shadowvpn_%s_server", name);
	fprintf(fp, "server=%s\n", nvram_safe_get(&buffer[0]));
	sprintf(&buffer[0], "shadowvpn_%s_port", name);
	fprintf(fp, "port=%d\n", nvram_get_int(&buffer[0]));
	sprintf(&buffer[0], "shadowvpn_%s_password", name);
	fprintf(fp, "password=%s\n", nvram_safe_get(&buffer[0]));
	sprintf(&buffer[0], "shadowvpn_%s_mode", name);
	fprintf(fp, "mode=%s\n", nvram_safe_get(&buffer[0]));
	sprintf(&buffer[0], "shadowvpn_%s_concurrency", name);
	fprintf(fp, "concurrency=%d\n", nvram_get_int(&buffer[0]));
	sprintf(&buffer[0], "shadowvpn_%s_mtu", name);
	fprintf(fp, "mtu=%d\n", nvram_get_int(&buffer[0]));
	sprintf(&buffer[0], "shadowvpn_%s_intf", name);
	fprintf(fp, "intf=%s\n", nvram_safe_get(&buffer[0]));
	sprintf(&buffer[0], "shadowvpn_%s_net", name);
	fprintf(fp, "net=%s\n", nvram_safe_get(&buffer[0]));

	fprintf(fp, "up=%s\n", up_path);
	fprintf(fp, "down=%s\n", down_path);

	fprintf(fp, "pidfile=/var/run/shadowvpn_%s.pid\n", name);
	fprintf(fp, "logfile=/var/log/shadowvpn_%s.log\n", name);

        //append_custom_config(config_name, fp);
        if(NULL!=fp) fclose(fp);
	fp = NULL;

	sprintf(&buffer[0], "%s/%s.conf", SAVE_DIR, name);
	if ( check_if_file_exist(&buffer[0]) ){
		eval("cp", "-f", &buffer[0], config_path);
	}
        //use_custom_config(config_name, config_path);
}


void start_shadowvpn(const char *name)
{
	char buffer[BUF_SIZE];
	char config_name[64];
	char config_path[PATH_MAX];
	char pid_path[PATH_MAX];
	sprintf(config_name, "%s.conf", name);
	sprintf(config_path, "%s/%s", CONFIG_DIR, config_name);

	sprintf(pid_path, "/var/run/shadowvpn_%s.pid", name);

	sprintf(&buffer[0], "start_shadowvpn_%s", name);
	if (getpid() != 1) {
		notify_rc(&buffer[0]);
		return;
	}


	if ( check_if_file_exist(pid_path) )
	{
		logmessage("shadowvpn", "Warn %s already running!", name);
		return;
	}

        write_shadowvpn_conf(name);

        // Make sure module is loaded
        modprobe("tun");
        f_wait_exists("/dev/net/tun", 5);

	sprintf(&buffer[0], "shadowvpn_%s_state", name);
	nvram_set(&buffer[0], "1");	//initializing

	sprintf(&buffer[0], "shadowvpn -c %s -s start ", config_path);
        logmessage("shadowvpn", "starting by cmd: %s", &buffer[0]);
        /*
	if (! eval("shadowvpn", "-c", config_path, "-s", "start") )
	{
		logmessage("shadowvpn", "Error Starting ShadowVPN %s failed...", name);
		stop_shadowvpn(name);
		return;
	}
        */
	eval("shadowvpn", "-c", config_path, "-s", "start");
        logmessage("shadowvpn", "%s started", name);
	set_cf2nvram(name, config_path);
}

void stop_shadowvpn(const char *name)
{
	char buffer[BUF_SIZE];
	char config_path[PATH_MAX];
	char pid_path[PATH_MAX];
	sprintf(config_path, "%s/%s.conf",CONFIG_DIR, name);
	sprintf(pid_path, "/var/run/shadowvpn_%s.pid", name);

	if (! check_if_file_exist(config_path) ){
        	logmessage("shadowvpn", "%s config file not exist.", config_path);
		return;
	}

	sprintf(&buffer[0], "stop_shadowvpn_%s", name);
	if (getpid() != 1) {
                notify_rc(&buffer[0]);
		return;
	}

	if (! check_if_file_exist(pid_path) ){
		logmessage("shadownvpn", "Error %s pid file not exist!", pid_path);
		return;
	}

	// Stop the VPN client
	logmessage("shadowvpn","Stopping ShadowVPN %s ...", name);

        eval("shadowvpn", "-c", config_path, "-s", "stop");

	sprintf(&buffer[0], "shadowvpn_%s_state", name);
	nvram_set(&buffer[0], "0");	//initializing
	logmessage("shadowvpn","ShadowVPN %s stopped.", name);
}
