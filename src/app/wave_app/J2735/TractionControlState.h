/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_TractionControlState_H_
#define	_TractionControlState_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TractionControlState {
	TractionControlState_unavailable	= 0,
	TractionControlState_off	= 1,
	TractionControlState_on	= 2,
	TractionControlState_engaged	= 3
} e_TractionControlState;

/* TractionControlState */
typedef long	 TractionControlState_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TractionControlState;
asn_struct_free_f TractionControlState_free;
asn_struct_print_f TractionControlState_print;
asn_constr_check_f TractionControlState_constraint;
ber_type_decoder_f TractionControlState_decode_ber;
der_type_encoder_f TractionControlState_encode_der;
xer_type_decoder_f TractionControlState_decode_xer;
xer_type_encoder_f TractionControlState_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _TractionControlState_H_ */
#include <asn_internal.h>
