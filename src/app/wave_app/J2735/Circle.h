/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_Circle_H_
#define	_Circle_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Position3D.h"
#include <NativeInteger.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Circle__raduis_PR {
	Circle__raduis_PR_NOTHING,	/* No components present */
	Circle__raduis_PR_radiusSteps,
	Circle__raduis_PR_miles,
	Circle__raduis_PR_km
} Circle__raduis_PR;

/* Circle */
typedef struct Circle {
	Position3D_t	 center;
	struct Circle__raduis {
		Circle__raduis_PR present;
		union Circle__raduis_u {
			long	 radiusSteps;
			long	 miles;
			long	 km;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} raduis;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Circle_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Circle;

#ifdef __cplusplus
}
#endif

#endif	/* _Circle_H_ */
#include <asn_internal.h>
