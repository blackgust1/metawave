/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_VehicleReferenceLane_H_
#define	_VehicleReferenceLane_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LaneNumber.h"
#include "LaneWidth.h"
#include "VehicleLaneAttributes.h"
#include "NodeList.h"
#include "ConnectsTo.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NodeList;

/* VehicleReferenceLane */
typedef struct VehicleReferenceLane {
	LaneNumber_t	 laneNumber;
	LaneWidth_t	*laneWidth	/* OPTIONAL */;
	VehicleLaneAttributes_t	 laneAttributes;
	NodeList_t	 nodeList;
	struct NodeList	*keepOutList	/* OPTIONAL */;
	ConnectsTo_t	*connectsTo	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VehicleReferenceLane_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VehicleReferenceLane;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleReferenceLane_H_ */
#include <asn_internal.h>
