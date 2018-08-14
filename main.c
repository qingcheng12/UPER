#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wait.h>
#include <errno.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <stdint.h>

#include <Msg.h>

#define MAXLEN_256 256

char sendbuf[64];

/* Msg */
typedef struct _SpatMsg {
	long	 length;
	long	 latitude;
	long	 longitude;
	long	 heading;
	long	 state;
	long	 time;
	long	 pading;
} SpatMsg;



// local udp socket
int sockFd;

struct sockaddr_in addr_local;
struct sockaddr_in addr_Client;

tDTLSocket DTL;

void Encode_Msg(SpatMsg *spatmsg);
void Decode_Receive(char *recvBuf);

#define dbg_printf(f, a...)                                       \
    do {                                                          \
        fprintf(stdout, "%s(%d): " f, __func__, __LINE__, ## a);  \
    }while (0)

#define ERR_EXIT(m)	\
	do	\
	{	\
		perror(m);	\
		exit(EXIT_FAILURE);	\
	} while(0)

int main()
{
	int Res = -ENOSYS;
	int option = 1; // 设置socket ip地址可复用
//	int so_broadcast = 1; //设置socket为广播模式

	// 填充信号灯消息
	SpatMsg *msg;

	// 编码发送
	Encode_Msg(msg);

	// 接收信息解析
	char  recvBuf[MAXLEN_256];

    return 0;
}

// 编码发送
void Encode_Msg(SpatMsg *spatmsg)
{
	Msg_t *msg; /* Type to encode */
    asn_enc_rval_t ec; /* Encoder return value */

    /* Allocate the Rectangle_t */
    msg = (Msg_t*)calloc(1, sizeof(Msg_t)); /* not */
    printf("length = %d\n", sizeof(Msg_t));
    if(!msg) {
        perror("calloc() failed");
        exit(71); /* better, EX_OSERR */
    }

    /* Initialize the Rectangle members , 写死测试*/
    msg->length = 4; /* any random value */
    msg->latitude = 295312345; /* any random value */
    msg->longitude = 1063623456;
    msg->heading = 0x01;
    msg->state = 0x01;
    msg->time = 5;

    // 填充信号灯消息
//    msg->length = spatmsg->length; /* any random value */
//	msg->latitude = spatmsg->latitude; /* any random value */
//	msg->longitude = spatmsg->longitude;
//	msg->heading = spatmsg->heading;
//	msg->state = spatmsg->state;
//	msg->time = spatmsg->time;
//	msg->pading = spatmsg->pading;


    // 对从C结构编码成ASN1格式数据buf
	// UPER
	ec = uper_encode_to_buffer(&asn_DEF_Msg, msg, sendbuf, 64);
    if(ec.encoded  == -1) {
        fprintf(stderr,
            "Could not encode MessageFrame (at %s)\n",
            ec.failed_type ? ec.failed_type->name : "unknown");
        exit(65); /* better, EX_DATAERR */
    } else {
        fprintf(stderr, "Created %s with PER encoded MessageFrame\n",
            "");
    }


    /* Also print the constructed Rectangle XER encoded (XML) */
    xer_fprint(stdout, &asn_DEF_Msg, msg)；
	    
   Decode_Receive(sendbuf);


}



// 解析处理
void Decode_Receive(char *recvBuf)
{
	asn_dec_rval_t rval;
	Msg_t *msg1 = (Msg_t *)calloc(1, sizeof(Msg_t));
	// UPER 解码
	asn_codec_ctx_t *opt_codec_ctx = 0;
	rval = uper_decode(opt_codec_ctx, &asn_DEF_Msg, (void **) &msg1,
			recvBuf, 256, 0, 0);
	if (rval.code == RC_OK) {
		printf("\n ----- decode ASN success-----\n");
	} else {
		printf("\n ----- decode ASN failed ------\n");
		exit(1);
	}

	// printf the msg
	xer_fprint(stdout, &asn_DEF_Msg, msg1);

	// 执行其他业务


}
