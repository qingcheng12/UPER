/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "MsgTest"
 * 	found in "try.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_Msg_H_
#define	_Msg_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Msg */
typedef struct Msg {
	long	 length;
	long	 latitude;
	long	 longitude;
	long	 heading;
	long	 state;
	long	 time;
	long	 pading;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Msg_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Msg;

#ifdef __cplusplus
}
#endif

#endif	/* _Msg_H_ */
#include <asn_internal.h>
