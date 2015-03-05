/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_WiperStatusRear_H_
#define	_WiperStatusRear_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum WiperStatusRear {
	WiperStatusRear_unavailable	= 0,
	WiperStatusRear_off	= 1,
	WiperStatusRear_intermittent	= 2,
	WiperStatusRear_low	= 3,
	WiperStatusRear_high	= 4,
	WiperStatusRear_washerInUse	= 126,
	WiperStatusRear_automaticPresent	= 127
	/*
	 * Enumeration is extensible
	 */
} e_WiperStatusRear;

/* WiperStatusRear */
typedef long	 WiperStatusRear_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_WiperStatusRear;
asn_struct_free_f WiperStatusRear_free;
asn_struct_print_f WiperStatusRear_print;
asn_constr_check_f WiperStatusRear_constraint;
ber_type_decoder_f WiperStatusRear_decode_ber;
der_type_encoder_f WiperStatusRear_encode_der;
xer_type_decoder_f WiperStatusRear_decode_xer;
xer_type_encoder_f WiperStatusRear_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _WiperStatusRear_H_ */
#include <asn_internal.h>
