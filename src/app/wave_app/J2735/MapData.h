/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_MapData_H_
#define	_MapData_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DSRCmsgID.h"
#include "MsgCount.h"
#include "DescriptiveName.h"
#include "LayerType.h"
#include "LayerID.h"
#include "MsgCRC.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DataParameters;
struct Intersection;

/* MapData */
typedef struct MapData {
	DSRCmsgID_t	 msgID;
	MsgCount_t	 msgCnt;
	DescriptiveName_t	*name	/* OPTIONAL */;
	LayerType_t	*layerType	/* OPTIONAL */;
	LayerID_t	*layerID	/* OPTIONAL */;
	struct MapData__intersections {
		A_SEQUENCE_OF(struct Intersection) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *intersections;
	struct DataParameters	*dataParameters	/* OPTIONAL */;
	MsgCRC_t	 crc;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MapData_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MapData;

#ifdef __cplusplus
}
#endif

#endif	/* _MapData_H_ */
#include <asn_internal.h>
