/** @file athdev.c
  * @brief attached device daemon
  *
  * Based on Netgear spec, to implement attached device feature.
  *
  * modification history
  * --------------------
  * 01a,29aug13, Eason Liu written.
  *
  * @author Eason Liu (eason.liu@wnc.com.tw)
  * @date	29aug13
  *
  * All code (c)2012 WNC Wistron NeWeb Corp. all rights reserved
  *
  * TODO: 1. name query: ip2name(char *ip);
  *       2. RARP: implemented in send_arp.c, but didn't it works or not
  */
  
#include <stdio.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <string.h>

#ifdef _SQLITE_
  #include <sqlite3.h>
  #include <sqliteExtLib.h>
  #include <sqlextlib/sql_ext_lib.h>
#endif

#define VERSION				V1.1
#define MAX_STRING_SIZE			128
#define WEB_DB_MAX_RETRIES              100
#define WEB_NUM_MILLIS_TO_SLEEP         100
#define POST_BUF_SIZE                   30000

unsigned char hostname[64];

#ifdef _SQLITE_
  static SQLITE_BUSY_HANDLER_ARG bhWebArg = {"", WEB_DB_MAX_RETRIES, WEB_NUM_MILLIS_TO_SLEEP};
  char * pDBFile;
  sqlite3 * pWebDb;
#endif

int just_count = 0;
int debug = 0;

static char * ip2host( char *ip );
static char *mac2if(char *mac);
static int ip2name(char *ip);

void scanAttachedDevice();

int scanDhcpLease();
int scanWiFiAssoc();
int scanARPtable();
int isARPReply(char *ipaddr);

int webOpenDB (char * dbfile)
{
#ifdef _SQLITE_
    if (sqlite3_open (dbfile, &pWebDb) != SQLITE_OK)
    {
        printf ("unable to open the DB file %s\n", dbfile);
        return -1;
    }

    sqlite3_busy_handler (pWebDb, sqliteBusyHandler, &bhWebArg);
    pDBFile = dbfile;
    printf("pDBFile: %s \n",pDBFile);
    if (!pWebDb)
    {
        printf("init pWebDb failed\n");
        return -1;
    }
#endif
    return 0;    
}

void webCloseDb ()
{
 #ifdef _SQLITE_
    if (pWebDb)
        sqlite3_close (pWebDb);
    else
        printf("close db failed\n");

#endif
}
/**
 * @brief main function
 *
 * This is the main function that starts the demo test process.
 *
 * @return ERROR  - could not start demo test process
 *          OK     - otherwise
 */
int main(int argc, char ** argv)
{
    char sysCmd[MAX_STRING_SIZE];
    int c;

    if(argc)
    {
        while ((c = getopt(argc, argv, "lvds")) != -1)
        {
            switch (c) 
	    {
            case 'l':
                just_count = 1;
                break;
            case 'd':
                debug = 1;
                break;
            case 'v':
                snprintf(sysCmd, sizeof(sysCmd), "Attachded device utility %s.\n", "V1.1");
		PLATFORM_printf(sysCmd);
                break;
	    }
	}
    }

#ifdef _SQLITE_
    if ( 0 == just_count )
    {
        if (webOpenDB("/tmp/system.db")<0)
            return -1;
    }
    snprintf(sysCmd, sizeof(sysCmd), "sqlite3 /tmp/system.db \"delete from attacheddevice\"");
    system(sysCmd);    
#endif    

//    system("touch /tmp/attaching");
    
    
    scanAttachedDevice();

#ifdef _SQLITE_    
    if ( 0 == just_count )
    {
        webCloseDb(); 
    }
#endif    
//    remove("/tmp/attaching");
    return 0;
}

/*
 * Send ARP packets to all IP addresses belong to our attach device table, re-send ARP 2 
 * times and wait 500 ms in each re-send. This is to prevent those attach devices don’t receive 
 * our ARP packet. Wait 3 seconds to collect all replies. If any client doesn’t reply, then remove 
 * it from our attach device table.
 */
int isARPReply(char *ipaddr)
{
    int res = -1;
    char *pLanIpAddr = NULL;
    char *pLanMACAddr = NULL;

    //TODO: fix crash later. mark it to avoid R2 crash
    return 0;

#ifdef _SQLITE_    
    sql_getValue(pWebDb, "LAN", "IpAddress", 1, &pLanIpAddr);
    sql_getValue(pWebDb, "MacTable", "MacAddress", 1, &pLanMACAddr);
    //printf("%s, %s, %s\n", __func__, pLanIpAddr, pLanMACAddr);
    res = send_arp_request(pLanIpAddr, pLanMACAddr, ipaddr, "FF:FF:FF:FF:FF:FF", 1);
   // printf("arp_result=%d\n", res);
#endif

    if (!res)
    {
  //      if (pLanIpAddr) free(pLanIpAddr);
  //      if (pLanMACAddr) free(pLanMACAddr);
        return res;
    }
        
    PLATFORM_SleepMSec(500);  // According to spec, wait 500ms then resend if first arp doesn't reply

    res = send_arp_request(pLanIpAddr, pLanMACAddr, ipaddr, "FF:FF:FF:FF:FF:FF", 1);

//    if (pLanIpAddr) free(pLanIpAddr);
//    if (pLanMACAddr) free(pLanMACAddr);
    return res;  
}

int scanDhcpLease()
    {
    FILE *fp;
    char tmpmac[30];
    char sysCmd[256];
    char tmpexpires[64];
    unsigned long expires;
    unsigned d, h, m;

    // This structure need the same with your udhcpd
    struct dhcpOfferedAddr 
    {
        unsigned char mac[16];
        unsigned long ip;
        unsigned long expires;
        unsigned char hostname[64];
    } lease;
    
    struct in_addr addr;

    snprintf(sysCmd, sizeof(sysCmd), "sqlite3 /tmp/system.db \"delete from DhcpLeasedClients\"");
    system(sysCmd);
    
    system("killall -q -USR1 udhcpd");
    fp = fopen("/tmp/udhcpd0.leases", "r");
        
        if (NULL == fp)
        {
            return -1;
        }
    
        while (fread(&lease, 1, sizeof(lease), fp) == sizeof(lease)) 
        {
    
            if (strlen(lease.hostname) > 0)
            { 
                sprintf(tmpmac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    lease.mac[0], lease.mac[1], lease.mac[2],
                    lease.mac[3], lease.mac[4], lease.mac[5]);

                addr.s_addr = lease.ip;
                expires = ntohl(lease.expires);
                d = expires / (24*60*60); expires %= (24*60*60);
                h = expires / (60*60); expires %= (60*60);
                m = expires / 60; expires %= 60;

                if (d) 
                    snprintf(tmpexpires, sizeof(tmpexpires), "%u days %02u:%02u:%02u\n", d, h, m, (unsigned)expires);


                //printf("Marching %s, hostname=%s\n", inet_ntoa(addr), lease.hostname);
                if (!isARPReply(inet_ntoa(addr)))
                    {
                    snprintf(sysCmd, sizeof(sysCmd), "sqlite3 /tmp/system.db \"insert into attacheddevice  (AttchedType, IpAddress, MacAddress, DeviceName) values ('%s', '%s', '%s', '%s')\"", mac2if(tmpmac), inet_ntoa(addr), tmpmac, lease.hostname);
                    printf("[debug] %s\n", sysCmd);
                    system(sysCmd);
                    }
                else
                    printf("%s didn't exist anymore...\n", inet_ntoa(addr));

                //sqlite3 /tmp/system.db "insert into DhcpLeasedClients (LogicalIfname, hostName, IpAddr, MacAddr, Timeout, clientIf) values ('1', '"$1"', '"$2"', '"$3"', '"$4"','"$CliIF"')";
                snprintf(sysCmd, sizeof(sysCmd), "sqlite3 /tmp/system.db \"insert into DhcpLeasedClients (LogicalIfname, hostName, IPAddress, MacAddress, Timeout, clientIf)  values ('br0', '%s', '%s', '%s', '%s', '%s')\"", 
                    lease.hostname, inet_ntoa(addr), tmpmac, tmpexpires, mac2if(tmpmac));
               // printf("[debug] %s\n", sysCmd);
                system(sysCmd);

               
                return 0;
            }
        }
    fclose(fp);  

    fp = fopen("/tmp/udhcpd1.leases", "r");
        
        if (NULL == fp)
        {
            return -1;
        }
    
        while (fread(&lease, 1, sizeof(lease), fp) == sizeof(lease)) 
        {
             if (strlen(lease.hostname) > 0)
            { 
                sprintf(tmpmac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    lease.mac[0], lease.mac[1], lease.mac[2],
                    lease.mac[3], lease.mac[4], lease.mac[5]);

                addr.s_addr = lease.ip;
                //printf("Marching %s, hostname=%s\n", inet_ntoa(addr), lease.hostname);
                if (!isARPReply(inet_ntoa(addr)))
                    {
                    snprintf(sysCmd, sizeof(sysCmd), "sqlite3 /tmp/system.db \"insert into attacheddevice  (AttchedType, IpAddress, MacAddress, DeviceName) values ('%s', '%s', '%s', '%s')\"", mac2if(tmpmac), inet_ntoa(addr), tmpmac, lease.hostname);
                    //printf("[debug] %s\n", sysCmd);
                    system(sysCmd);
                    }
                else
                    printf("%s didn't exist anymore...\n", inet_ntoa(addr));

                return 0;
            }
        }
    fclose(fp);   
    return 0;
    }

// Todo
int scanWiFiAssoc()
    {
    FILE *p;
    char sysCmd[64];
    char buf[256];
    int i = 0;
    int res = -1;

/*
    snprintf(sysCmd, sizeof(sysCmd), "wl -i eth1 assoclist");

    if ((p = popen(sysCmd, "r")) != NULL)
        {
            while(fgets(buf, sizeof(buf), p))
                {
                    if( 0 != strlen(buf))
                        {
                            printf("wifi0: assoc:%s\n", buf); 
                            res = send_rarp_request("192.168.1.1", "C8:D7:19:52:72:54", "0.0.0.0", "00:1B:77:D6:76:60", 1);
                           if (!res)
                               printf("Resolved ip from %s\n", buf);
                            // TODO:how to get ip from mac?
                        }
                }
            pclose(p);
        }
*/
    return 0;
    }

int scanARPtable()
    {
    FILE *f;
    char s[512];
    char ip[16];
    char mac[18];
    char dev[17];
    unsigned int flags;
    char sysCmd[256];
    int count=0;
    /*
    cat /proc/net/arp
    IP address       HW type     Flags       HW address            Mask     Device
    192.168.0.1      0x1         0x2         00:01:02:03:04:05     *        vlan1
    */
    if ((f = fopen("/proc/net/arp", "r")) != NULL) 
        {
        while (fgets(s, sizeof(s), f)) 
            {
            if ( 0 == just_count)
                {
                if (sscanf(s, "%15s %*s 0x%X %17s %*s %16s", ip, &flags, mac, dev) != 4) continue;
                if ((strlen(mac) != 17) || (strcmp(mac, "00:00:00:00:00:00") == 0)) continue;
                if (flags == 0) continue;
                if (0 != strncmp("br0", dev, 3)) continue;

                printf("['%s','%s','%s']\n", ip, mac, dev);
                //  printf("mac:%s is %s\n", mac, iswifi(mac));
                //  printf("arptable: client:%s\n", ip);

                //CliIF: wired/radio1/guest1/radio2/guest2
                //sqlite+ /tmp/system.db "insert into AttachedDevice (AttchedType, IpAddress, MacAddress, DeviceName) values ('$CliIF', '"$2"', '"$3"', '"$1"')";

                if (!isARPReply(ip))
                    {
                    snprintf(sysCmd, sizeof(sysCmd), "sqlite3 /tmp/system.db \"insert into attacheddevice  (AttchedType, IpAddress, MacAddress, DeviceName) values ('%s', '%s', '%s', '%s')\"", 
                        mac2if(mac), ip, mac, ip2host(ip));
                    //  printf("%s\n", sysCmd);
                    system(sysCmd);
                    }  
                else
                    printf("%s didn't exist anymore...\n", ip);  
                }
            else
                {
                    if (sscanf(s, "%15s %*s 0x%X %17s %*s %16s", ip, &flags, mac, dev) != 4) continue;
                    if ((strlen(mac) != 17) || (strcmp(mac, "00:00:00:00:00:00") == 0)) continue;
                    if (flags == 0) continue;
                    if (0 != strncmp("br0", dev, 3)) continue;

                    //printf("['%s','%s','%s']\n", ip, mac, dev);

                    count++;
                }  
            }
        if ( 1 == just_count)   printf("%d\n", count);   
        fclose(f);
        }
    }

// Todo
int extArpScanby()
    {
        //arp-scan -l -Nqg -I br0
        return 0;
    }

 /**
 * @brief arp dev function
 *
 * Updating arp client list to system database
 *
 * @return ERROR  - could not start demo test process
 *          OK     - otherwise
 */

void scanAttachedDevice()
{
    char sysCmd[MAX_STRING_SIZE];
    
    /* Step 1:
    To list all dhcp client, it will cover most client list, whatever WiFi or wired.
    */
//    if (0 != scanDhcpLease())
//	printf("scan dhcplease fail...\n");
    
    /* Step 2:
    To scan wifi associated list, to find out if any wifi user using static IP address.
    Need to 1) use RARP to get corresponding IP address, 2) send a name query packet to 
    obtain its hostname if possible.
    */
//    if (0 != scanWiFiAssoc())
//        printf("scan WiFiAssoc fail...\n");       
    
    /* Step 3:
    To scan ARP table, to find out if any wired user using static IP address.
    Need 1) send a name query packet to obtain its hostname if possible.
    */
    if (0 != scanARPtable())
    {
        printf("scan ARP table fail...\n");     
    }
}

 /**
 * @brief transfer mac to if name function
 * @return hostname
 */
 
static char *mac2if(char *mac)
    {
    FILE *p;
    char sysCmd[64];
    char buf[256];
    int i=0;

    while  (mac[i]!= '\0' )
    {
        if  ( islower (mac[i]))  
            {   
            mac[i]= toupper (mac[i]);   
            }
        i++;   
    }   
  // printf("mac=%s\n", mac);

    snprintf(sysCmd, sizeof(sysCmd), "wl -i eth1 assoclist | grep %s", mac);

    if ((p = popen(sysCmd, "r")) != NULL)
        {
            while(fgets(buf, sizeof(buf), p))
                {
                    if( 0 != strlen(buf))
                        {
                            return "radio1";
                        }
                }
            pclose(p);
        }

    snprintf(sysCmd, sizeof(sysCmd), "wl -i wl0.1 assoclist | grep %s", mac);

    if ((p = popen(sysCmd, "r")) != NULL)
        {
            while(fgets(buf, sizeof(buf), p))
                {
                    if( 0 != strlen(buf))
                        {
                            return "guest1";
                        }
                }
            pclose(p);
        }

    snprintf(sysCmd, sizeof(sysCmd), "wl -i eth2 assoclist | grep %s", mac);

    if ((p = popen(sysCmd, "r")) != NULL)
        {
            while(fgets(buf, sizeof(buf), p))
                {
                    if( 0 != strlen(buf))
                        {
                            return "radio2";
                        }
                }
            pclose(p);
        }

    snprintf(sysCmd, sizeof(sysCmd), "wl -i wl1.1 assoclist | grep %s", mac);

    if ((p = popen(sysCmd, "r")) != NULL)
        {
            while(fgets(buf, sizeof(buf), p))
                {
                    if( 0 != strlen(buf))
                        {
                            return "guest2";
                        }
                }
            pclose(p);
        }

    return "wired";
    }
    
 /**
 * @brief ip to hostname function
 *
 * according to netgear spec, the priority as below:
 *  1) to search from dhcp server first
 *  2) to send name query if no result from dhcp server
 *
 * @return hostname
 */

static char *ip2host( char *ip )
{
    FILE *fp;
    
    // This structure need the same with your udhcpd
    struct dhcpOfferedAddr 
    {
        unsigned char mac[16];
        unsigned long ip;
        unsigned long expires;
        unsigned char hostname[64];
    } lease;
    
    struct in_addr addr;
    
    system("killall -q -USR1 udhcpd");
    fp = fopen("/tmp/udhcpd0.leases", "r");
        
        if (NULL == fp)
        {
            ip2name(ip);
            if (strlen(hostname) > 0)
                return hostname;
            else
                return "";
        }
    
        while (fread(&lease, 1, sizeof(lease), fp) == sizeof(lease)) 
        {
    
            if (strlen(lease.hostname) > 0)
            { 
                addr.s_addr = lease.ip;
                if ( 0 == strcmp(inet_ntoa(addr), ip))
                {
                    //printf("Marching %s, hostname=%s\n", inet_ntoa(addr), lease.hostname);
                    //strncpy(lease.hostname, *hostname, sizeof(lease.hostname));
                   // memcpy(*hostname, lease.hostname, sizeof(lease.hostname));
                   //return 0;
                    strncpy(hostname, lease.hostname, 64);
                    fclose(fp);  
                    return hostname;
                }   
            }
        }
    fclose(fp);  

    fp = fopen("/tmp/udhcpd1.leases", "r");
        
        if (NULL == fp)
        {
            ip2name(ip);
            if (strlen(hostname) > 0)
                return hostname;
            else
                return "";
        }
    
        while (fread(&lease, 1, sizeof(lease), fp) == sizeof(lease)) 
        {
    
            if (strlen(lease.hostname) > 0)
            { 
                addr.s_addr = lease.ip;
                if ( 0 == strcmp(inet_ntoa(addr), ip))
                {
                    //printf("Marching %s, hostname=%s\n", inet_ntoa(addr), lease.hostname);
                    //strncpy(lease.hostname, *hostname, sizeof(lease.hostname));
                   // memcpy(*hostname, lease.hostname, sizeof(lease.hostname));
                   //return 0;
                    strncpy(hostname, lease.hostname, 64);
                    fclose(fp);  
                    return hostname;
                }   
            }
        }
    fclose(fp);

    ip2name(ip);
    if (strlen(hostname) > 0)
        return hostname;
    else
        return "";
}

 /**
 * @brief transfer ip to host name function (name query)
 * @return hostname
 */
 
static int ip2name(char *ip)
    {
    FILE *p;
    char sysCmd[128];
    char buf[64];
    char* find = 0;

    sprintf(sysCmd, "nmblookup -A %s | grep \"<00> -         \" | cut -d \" \" -f1", ip);

    if ((p = popen(sysCmd, "r")) != NULL)
        {
        while(fgets(buf, sizeof(buf), p))
            {
                int len = strlen(buf);
                if (buf[len-1] == '\n')
                    buf[len-1] = '\0';

                if( 0 != strlen(buf))
                    {
                        printf("%s from %s\n", buf, ip);
                        strncpy(hostname, buf, 64);
                        // TODO:how to get ip from mac?
                    }
            }
            pclose(p);
        }   
    return 0;
    }

