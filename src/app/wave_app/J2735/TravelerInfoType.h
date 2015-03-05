/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_TravelerInfoType_H_
#define	_TravelerInfoType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TravelerInfoType {
	TravelerInfoType_unknown	= 0,
	TravelerInfoType_advisory	= 1,
	TravelerInfoType_roadSignage	= 2,
	TravelerInfoType_commercialSignage	= 3
	/*
	 * Enumeration is extensible
	 */
} e_TravelerInfoType;

/* TravelerInfoType */
typedef long	 TravelerInfoType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TravelerInfoType;
asn_struct_free_f TravelerInfoType_free;
asn_struct_print_f TravelerInfoType_print;
asn_constr_check_f TravelerInfoType_constraint;
ber_type_decoder_f TravelerInfoType_decode_ber;
der_type_encoder_f TravelerInfoType_encode_der;
xer_type_decoder_f TravelerInfoType_decode_xer;
xer_type_encoder_f TravelerInfoType_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _TravelerInfoType_H_ */
#include <asn_internal.h>