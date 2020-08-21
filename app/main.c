/***************************************************************************** 
* 
* File Name : main.c
* 
* Description: main 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-14
*****************************************************************************/ 
#include <string.h>
#include "wm_include.h"
#include "wm_sockets.h"
#include "wm_timer.h"


#define USER_TASK_STK_SIZE      512
#define USER_TASK_PRIO          32
static u32 user_task_stk[USER_TASK_STK_SIZE];

tls_os_queue_t *sprinkler_management_q = NULL;

int demo_connect_net(char *ssid, char *pwd);
int is_supported_cmd(u8 cmd);
void print_recv_buffer();
static tls_timer_irq_callback sprinkler_timer_cb(u8 *arg);


#define    DEMO_RAW_SOCK_S_TASK_SIZE      256
tls_os_queue_t *demo_raw_sock_s_q = NULL;
static OS_STK DemoRawSockSTaskStk[DEMO_RAW_SOCK_S_TASK_SIZE]; 
ST_Demo_Sys gDemoSys;
struct tls_socket_desc socket_desc;

typedef struct {
    u32 header;
    u8 cmd;
    u32 duration_ms;
}__attribute__((packed)) cmd_msg_t;
cmd_msg_t * cmd_msg;
char err_msg[50];

#define CMD_SPRINKLER_ON            (69)
#define CMD_SPRINKLER_ESTOP         (42)
#define STATE_SPRINKLER_OFF         (1)
#define STATE_SPRINKLER_ON          (2)
#define RECEIVED_VALID_SOCKET_CMD   (1)
#define RECEIVED_TIMER_STOP         (2)

static u8 timer_id = 0;
struct tls_timer_cfg timer_cfg;

char my_tx_buf[20];

// user task
void sprinkler_management_task(void *data)
{
    // ms_per_cycle = 2
    void *task_comm_msg;
    u8 gpio_level = 0;
    u8 state = STATE_SPRINKLER_OFF;
    
    // init gpio 
    tls_gpio_cfg(WM_IO_PB_08, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    // note: WM_IO_PB_08 through WM_IO_PB_12 are all available to pinmux as gpios/pwm/adcs
    
    // init sprinkler timer
    timer_cfg.unit = TLS_TIMER_UNIT_MS;
	timer_cfg.timeout = 0; 
	timer_cfg.is_repeat = 0;
	timer_cfg.callback = sprinkler_timer_cb;
	timer_cfg.arg = NULL;
	timer_id = tls_timer_create(&timer_cfg);

    while(1)
    {
        tls_os_queue_receive(sprinkler_management_q, (void **)&task_comm_msg, 0, 0);
        switch((u32)task_comm_msg) {
            case RECEIVED_VALID_SOCKET_CMD: 
                // parse message and what to do here if valid header and cmd type
                switch (state) {
                    case STATE_SPRINKLER_OFF:
                        if (cmd_msg->cmd == CMD_SPRINKLER_ON) {

                            // turn on sprinkler
                            gpio_level = 1;
                            tls_gpio_write(WM_IO_PB_08, gpio_level);

                            // start hardware timer
                            timer_cfg.timeout = cmd_msg->duration_ms;
                            timer_id = tls_timer_create(&timer_cfg);
                            tls_timer_start(timer_id);

                            // transition to ON state
                            state = STATE_SPRINKLER_ON;

                            // send feedback
                            printf("turned sprinkler on! (%dms)\n", cmd_msg->duration_ms);
                            sprintf(err_msg, "turned sprinkler on! (%dms)\n", cmd_msg->duration_ms);
                            tls_socket_send(gDemoSys.socket_num, err_msg, 50);

                        } else {
                            // make sure the sprinkler is off
                            gpio_level = 0;
                            tls_gpio_write(WM_IO_PB_08, gpio_level);

                            // send feedback
                            printf("sprinkler already off!\n");
                            sprintf(err_msg, "sprinkler already off!\n");
                            tls_socket_send(gDemoSys.socket_num, err_msg, 50);
                        }
                        break;

                    case STATE_SPRINKLER_ON:
                        if (cmd_msg->cmd == CMD_SPRINKLER_ESTOP) {
                        
                            // turn the sprinkler off
                            gpio_level = 0;
                            tls_gpio_write(WM_IO_PB_08, gpio_level);

                            // turn off timer
                            tls_timer_stop(timer_id);
                            tls_timer_destroy(timer_id);

                            // transition to OFF state
                            state = STATE_SPRINKLER_OFF;                            

                            // send feedback
                            printf("turned sprinkler off!\n");
                            sprintf(err_msg, "turned sprinkler off!\n");
                            tls_socket_send(gDemoSys.socket_num, err_msg, 50);
                        } else {
                            /* restart the timer with new duration_ms */

                            // turn off timer
                            tls_timer_stop(timer_id);
                            tls_timer_destroy(timer_id);

                            // start hardware timer
                            timer_cfg.timeout = cmd_msg->duration_ms;
                            timer_id = tls_timer_create(&timer_cfg);
                            tls_timer_start(timer_id);

                            // send feedback
                            printf("restarting sprinkler timer! (%dms)\n", cmd_msg->duration_ms);
                            sprintf(err_msg, "restarting sprinkler timer! (%dms)\n", cmd_msg->duration_ms);
                            tls_socket_send(gDemoSys.socket_num, err_msg, 50);
                        }

                        break;

                    default:
                        printf("how the fuck did you get to this state??\n");
                        sprintf(err_msg, "how the fuck did you get to this state??\n");
                        tls_socket_send(gDemoSys.socket_num, err_msg, 50);
                        break;
                } // end switch(state)
              
                // clear buffer after handling socket data
                memset(cmd_msg, 0, sizeof(cmd_msg_t));

                // send a nice message back
                printf("successfully completed command\n");
                break;

            case RECEIVED_TIMER_STOP:
                printf("received timer stop. stopping sprinkler...\n");
                gpio_level = 0;
                tls_gpio_write(WM_IO_PB_08, gpio_level);
                state = STATE_SPRINKLER_OFF;
                break;

            default:
                printf("unrecognized blinky LED task_comm_msg\n");
                break;

        } // end received task comm msg
    } // end task's infinite while loop 
} // end sprinkler management task

int is_supported_cmd(u8 cmd) {
    return ( (cmd==CMD_SPRINKLER_ON) || (cmd==CMD_SPRINKLER_ESTOP) );
}

static tls_timer_irq_callback sprinkler_timer_cb(u8 *arg)
{
    printf("\n==== sprinkler timer stop!!! ==== \n");	
    tls_timer_stop(timer_id); // If the timer needs to be used in the future, do not destroy it and no longer use it
                                // It needs to be destroyed, otherwise repeated application for TIMER will fail
    tls_timer_destroy(timer_id);

    // tell sprinkler to shut off now
    tls_os_queue_send(sprinkler_management_q, (void *)RECEIVED_TIMER_STOP, 0);
}

void print_recv_buffer() {
    printf("\n\nreceived data[%d]:\nhex:\t0x", gDemoSys.sock_rx_data_len);
    for (int i=0; i<gDemoSys.sock_rx_data_len; i++){
        printf("%X", gDemoSys.sock_rx[i]);
    }
    printf("\n\tascii:\t%s\n", gDemoSys.sock_rx);
}

err_t  raw_sk_server_recv(u8 skt_num, struct pbuf *p, err_t err)
{
	int offset = 0;
	// printf("socket_recv : %s\n", p->payload); 
	do
	{
		gDemoSys.sock_rx_data_len = pbuf_copy_partial(p, gDemoSys.sock_rx, DEMO_BUF_SIZE, offset);
		if(gDemoSys.sock_rx_data_len == 0)
			break;
		offset += gDemoSys.sock_rx_data_len;
		tls_os_queue_send(demo_raw_sock_s_q,(void *)DEMO_MSG_SOCKET_RECEIVE_DATA, 0);

	}while(offset < p->tot_len);
    
    print_recv_buffer();
	
	if (p) {
        pbuf_free(p);
    }
        
	return ERR_OK;
}

err_t raw_sk_server_connected(u8 skt_num,  err_t err)
{
	printf("connected socket num=%d,err=%d\n", skt_num,err);
	if(ERR_OK == err)
	{
		gDemoSys.socket_num = skt_num;
		gDemoSys.socket_ok = TRUE;
		gDemoSys.is_raw = 1;
		tls_os_queue_send(demo_raw_sock_s_q, (void *)DEMO_MSG_OPEN_UART, 0);
	}
	
	return ERR_OK;
}

void  raw_sk_server_err(u8 skt_num, err_t err)
{
	gDemoSys.socket_ok = FALSE;
	//printf("err socket num=%d,err=%d\n", skt_num,err);
	tls_os_queue_send(demo_raw_sock_s_q, (void *)DEMO_MSG_SOCKET_ERR, 0);
}

err_t raw_sk_server_poll(u8 skt_num)
{
	//printf("socketpoll skt_num : %d\n", skt_num);
	return ERR_OK;
}

err_t raw_sk_server_accept(u8 skt_num, err_t err)
{
	printf("accept socket num=%d, err= %d\n", skt_num, err);
	if(ERR_OK == err)
	{
		gDemoSys.socket_num = skt_num;
		gDemoSys.socket_ok = TRUE;
		gDemoSys.is_raw = 1;
		return ERR_OK;
	}
	return err;
}

void create_raw_socket_server_demo(void)
{		
	memset(&socket_desc, 0, sizeof(struct tls_socket_desc));
	socket_desc.recvf = raw_sk_server_recv;
	socket_desc.errf = raw_sk_server_err;
	socket_desc.pollf = raw_sk_server_poll;

	socket_desc.cs_mode = SOCKET_CS_MODE_SERVER;
	socket_desc.acceptf = raw_sk_server_accept;

	socket_desc.protocol = SOCKET_PROTO_TCP;
	socket_desc.port = LocalPort;
	printf("\nlisten port=%d\n",socket_desc.port);
	if(gDemoSys.socket_ok != TRUE)
	{
		tls_socket_create(&socket_desc);
	}
}

static void network_status_changed_event(u8 status )
{
	switch(status)
	{
	    case NETIF_WIFI_JOIN_SUCCESS:
	        printf("NETIF_WIFI_JOIN_SUCCESS\n");
            tls_os_queue_send(demo_raw_sock_s_q, (void *)DEMO_MSG_WJOIN_SUCCESS, 0);
            break;
        case NETIF_WIFI_JOIN_FAILED:
            printf("NETIF_WIFI_JOIN_FAILED\n");
            tls_os_queue_send(demo_raw_sock_s_q, (void *)DEMO_MSG_WJOIN_FAILD, 0);
            break;
        case NETIF_WIFI_DISCONNECTED:
            printf("NETIF_WIFI_DISCONNECTED\n");
            break;
		case NETIF_IP_NET_UP:
		{
			struct tls_ethif * tmpethif = tls_netif_get_ethif();
#if TLS_CONFIG_LWIP_VER2_0_3
			print_ipaddr(&tmpethif->ip_addr);
#if TLS_CONFIG_IPV6
			print_ipaddr(&tmpethif->ip6_addr[0]);
			print_ipaddr(&tmpethif->ip6_addr[1]);
			print_ipaddr(&tmpethif->ip6_addr[2]);
#endif
#else
			printf("net up ==> ip = %d.%d.%d.%d\n",ip4_addr1(&tmpethif->ip_addr.addr),ip4_addr2(&tmpethif->ip_addr.addr),
							 ip4_addr3(&tmpethif->ip_addr.addr),ip4_addr4(&tmpethif->ip_addr.addr));
#endif
            tls_os_queue_send(demo_raw_sock_s_q, (void *)DEMO_MSG_SOCKET_CREATE, 0);
        }
			break;
        default:
            printf("UNKONWN STATE:%d\n", status);
            break;
	}
}

static void demo_raw_sock_s_task(void *sdata)
{
    ST_Demo_Sys *sys = (ST_Demo_Sys *)sdata;
	void *msg;
	struct tls_ethif * ethif = tls_netif_get_ethif();
	
    
	printf("\nraw sock s task\n");

    // used for socket to receive data
	sys->sock_rx = tls_mem_alloc(DEMO_BUF_SIZE);
	if(NULL == sys->sock_rx)
	{
		printf("\nmalloc socket rx fail\n");
		return;
	}
	memset(sys->sock_rx, 0, DEMO_BUF_SIZE);	

    // if already on the net 
	if(ethif->status)	
	{
		tls_os_queue_send(demo_raw_sock_s_q, (void *)DEMO_MSG_SOCKET_CREATE, 0);
	}
	
	tls_netif_add_status_event(network_status_changed_event);
	for(;;) 
	{
		tls_os_queue_receive(demo_raw_sock_s_q, (void **)&msg, 0, 0);
		switch((u32)msg)
		{
			case DEMO_MSG_WJOIN_SUCCESS:
				break;
				
			case DEMO_MSG_SOCKET_CREATE:
                printf("creating raw socket server demo\n");
				create_raw_socket_server_demo();
				break;
				
			case DEMO_MSG_WJOIN_FAILD:
				if(sys->socket_num > 0)
				{
					sys->socket_num = 0;
					sys->socket_ok = FALSE;
				}
				break;

			case DEMO_MSG_SOCKET_RECEIVE_DATA:
                // received data, interpret as struct and print raw
                printf("got data!!\n");
                cmd_msg = (cmd_msg_t *) gDemoSys.sock_rx;
                printf("header: %d cmd: %d duration_ms: %d\n", cmd_msg->header, cmd_msg->cmd, cmd_msg->duration_ms );

                // check valid header
                if (cmd_msg->header != 42069) {
                    printf("invalid header: %d\n", cmd_msg->header);
                    sprintf(err_msg, "invalid header: %d\n", cmd_msg->header);
                    tls_socket_send(gDemoSys.socket_num, err_msg, 50);
                    break;
                } 
                // check supported command
                if ( ! is_supported_cmd(cmd_msg->cmd) ) {
                    printf("invalid command type: %d\n", cmd_msg->cmd);
                    sprintf(err_msg, "invalid command type: %d\n", cmd_msg->cmd);
                    tls_socket_send(gDemoSys.socket_num, err_msg, 50);
                    break;
                }
                // if valid cmd header and cmd type decide what to do
                tls_os_queue_send(sprinkler_management_q, (void *)RECEIVED_VALID_SOCKET_CMD, 0);
				break;

			case DEMO_MSG_SOCKET_ERR:
				tls_os_time_delay(200);
				printf("client socket closed\n");
                // open a new socket to accept more clients
				tls_socket_create(&socket_desc);
				break;

			default:
				break;
		}
	}

}

// connect to an SSID
int demo_connect_net(char *ssid, char *pwd)
{
	struct tls_param_ip *ip_param = NULL;
	u8 wireless_protocol = 0;

	if (!ssid) {
		return WM_FAILED;
	}

	// printf("\nssid:%s\n", ssid);
	// printf("password=%s\n",pwd);
	tls_wifi_disconnect();

	tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void*) &wireless_protocol, TRUE);
	if (TLS_PARAM_IEEE80211_INFRA != wireless_protocol)
	{
	    tls_wifi_softap_destroy();
	    wireless_protocol = TLS_PARAM_IEEE80211_INFRA;
        tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void*) &wireless_protocol, FALSE);
	}

	tls_wifi_set_oneshot_flag(0);

	ip_param = tls_mem_alloc(sizeof(struct tls_param_ip));
	if (ip_param)
	{
		tls_param_get(TLS_PARAM_ID_IP, ip_param, FALSE);
		ip_param->dhcp_enable = TRUE;
		tls_param_set(TLS_PARAM_ID_IP, ip_param, FALSE);
		tls_mem_free(ip_param);
	}

    u8 autoconnect = WIFI_AUTO_CNT_ON;
    tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_GET, &autoconnect);
    if(WIFI_AUTO_CNT_OFF == autoconnect)
    {
        autoconnect = WIFI_AUTO_CNT_ON;
        tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_SET, &autoconnect);
    }

	tls_netif_add_status_event(network_status_changed_event);
	tls_wifi_connect((u8 *)ssid, strlen(ssid), (u8 *)pwd, strlen(pwd));
	printf("\nplease wait connect net......\n");

	return WM_SUCCESS;
}

void UserMain(void)
{
    /* delay and print welcome message on boot */
    tls_os_time_delay(1 * HZ);  
    printf("\n\nWelcome to Philip's Sprinkler Management System, compile @%s %s\r\n", __DATE__, __TIME__);
	
    /* connect to wifi */
    printf("connecting to wifi...\n");
    demo_connect_net("NSA_Surveillance", "Harambe2k16COVID19");

    /* create raw socket server task */
    printf("connecting & creating socket server demo...\n");
    tls_os_queue_create(&demo_raw_sock_s_q, DEMO_QUEUE_SIZE);
	tls_os_task_create(NULL,
            "raw_socket_server",
			demo_raw_sock_s_task,
            (void *)&gDemoSys,
            (void *)DemoRawSockSTaskStk,          /* starting address of the task stack */
            DEMO_RAW_SOCK_S_TASK_SIZE * sizeof(u32), /* task stack size */
            DEMO_RAW_SOCKET_S_TASK_PRIO,
            0);

    /* create sprinkler management task */
    printf("sprinkler management task start ...\r\n");
    tls_os_queue_create(&sprinkler_management_q, DEMO_QUEUE_SIZE); // queue for comms
    tls_os_task_create(NULL,
            "sprinkler_management",
            sprinkler_management_task,
            (void*) 0,
            (void*) &user_task_stk,  
            USER_TASK_STK_SIZE *sizeof(u32),
            USER_TASK_PRIO,
            0);

}
