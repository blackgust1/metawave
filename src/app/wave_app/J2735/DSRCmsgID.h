/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_DSRCmsgID_H_
#define	_DSRCmsgID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DSRCmsgID {
	DSRCmsgID_reserved	= 0,
	DSRCmsgID_alaCarteMessage	= 1,
	DSRCmsgID_basicSafetyMessage	= 2,
	DSRCmsgID_basicSafetyMessageVerbose	= 3,
	DSRCmsgID_commonSafetyRequest	= 4,
	DSRCmsgID_emergencyVehicleAlert	= 5,
	DSRCmsgID_intersectionCollisionAlert	= 6,
	DSRCmsgID_mapData	= 7,
	DSRCmsgID_nmeaCorrections	= 8,
	DSRCmsgID_probeDataManagement	= 9,
	DSRCmsgID_probeVehicleData	= 10,
	DSRCmsgID_roadSideAlert	= 11,
	DSRCmsgID_rtcmCorrections	= 12,
	DSRCmsgID_signalPhaseAndTimingMessage	= 13,
	DSRCmsgID_signalRequestMessage	= 14,
	DSRCmsgID_signalStatusMessage	= 15,
	DSRCmsgID_travelerInformation	= 16
	/*
	 * Enumeration is extensible
	 */
} e_DSRCmsgID;

/* DSRCmsgID */
typedef long	 DSRCmsgID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DSRCmsgID;
asn_struct_free_f DSRCmsgID_free;
asn_struct_print_f DSRCmsgID_print;
asn_constr_check_f DSRCmsgID_constraint;
ber_type_decoder_f DSRCmsgID_decode_ber;
der_type_encoder_f DSRCmsgID_encode_der;
xer_type_decoder_f DSRCmsgID_decode_xer;
xer_type_encoder_f DSRCmsgID_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _DSRCmsgID_H_ */
#include <asn_internal.h>
