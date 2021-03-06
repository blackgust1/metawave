/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_DirectionOfUse_H_
#define	_DirectionOfUse_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DirectionOfUse {
	DirectionOfUse_forward	= 0,
	DirectionOfUse_reverse	= 1,
	DirectionOfUse_both	= 2
	/*
	 * Enumeration is extensible
	 */
} e_DirectionOfUse;

/* DirectionOfUse */
typedef long	 DirectionOfUse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DirectionOfUse;
asn_struct_free_f DirectionOfUse_free;
asn_struct_print_f DirectionOfUse_print;
asn_constr_check_f DirectionOfUse_constraint;
ber_type_decoder_f DirectionOfUse_decode_ber;
der_type_encoder_f DirectionOfUse_encode_der;
xer_type_decoder_f DirectionOfUse_decode_xer;
xer_type_encoder_f DirectionOfUse_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _DirectionOfUse_H_ */
#include <asn_internal.h>
