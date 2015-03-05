
#define WAVE_VERSION               				0x01

#define WAVE_SECURITY_VERSION               	0x01		/* 1609.2 5.2 참조. */

#define WSMP_VERSION               				0x02
#define WAVE_EID_WSM						0x80


#define VENDOR_SPECIFIC_CATEGORY			0x7F


/* 1609.2의 5.2 참조 : Message Type */
#define	MSG_TYPE_UNSECURED				0
#define	MSG_TYPE_SIGNED					1
#define	MSG_TYPE_ENCRYPTED				2

/* 1609.2의 5.8 참조 : APP ID */
#define	APPID_FULLY_SPECIFIED				0
#define	APPID_MATCH_ANY_ACM				1
#define	APPID_FROM_ISSUER					2

/* 1609.2 참조 : EncryptedContentType 정의 */
#define	ENCRYPTE_CONTENT_APP_DATA		0
#define	ENCRYPTE_CONTENT_SINGNED		1

/* 1609.2 참조 : SYMM_ALGORITHM 정의 */
#define	SYMM_ALGORITHM_AES_128_CCM		0



/********************	WAVE Management ID  ********************/
#define WMID_1609_0						0x00	      // by 1609.0
#define WMID_1609_1						0x01	      // by 1609.0
#define WMID_1609_2						0x02	      // by 1609.0
#define WMID_1609_3						0x03	      // by 1609.0
#define WMID_1609_5						0x05	      // by 1609.0
#define WMID_1609_11						0x0B	      // by 1609.0


#define IEEE1609_2_Version					0x01	      //by 1609.2

#define UNSECURED_WSA						0x00	      //by 1609.2
#define SECURED_WSA						0x01	      //by 1609.2

#define WSA_SUBTYPE						0x01	      //by 1609.3


/********************	WAVE Element ID  ********************/
/******************	WSA WAVE Element ID  ******************/
#define WSA_SERVICE_INFO_EID							0x01	
#define WSA_CHANNEL_INFO_EID							0x02
#define WSA_WRA_EID									0x03

/****************  Externsion WAVE Element ID  ****************/
#define EXT_WAVE_TRANSMIT_POWER_USED_EID			0x04
#define EXT_WAVE_WAVE_2D_LOCATION_EID				0x05
#define EXT_WAVE_3D_LOCATION_AND_CONFIDENCE_EID	0x06
#define EXT_WAVE_ADVERTISER_ID_EID					0x07
#define EXT_WAVE_PSC_EID								0x08
#define EXT_WAVE_IPV6ADDR_EID							0x09
#define EXT_WAVE_SVC_PORT_EID							0x0A
#define EXT_WAVE_PROVIDER_MAC_ADDR_EID				0x0B
#define EXT_WAVE_EDCA_PARAM_SET_EID					0x0C
#define EXT_WAVE_SECONDARY_DNS_EID					0x0D
#define EXT_WAVE_GW_MAC_ADDR_EID					0x0E
#define EXT_WAVE_CHANNEL_NUM_EID						0x0F
#define EXT_WAVE_DATARATE_EID						0x10
#define EXT_WAVE_REPEAT_RATE_EID						0x11
#define EXT_WAVE_COUNTRY_STRING_EID					0x12
#define EXT_WAVE_RCPI_THRESHOLD_EID					0x13
#define EXT_WAVE_WSA_COUNT_THRESHOLD_EID			0x14
#define EXT_WAVE_CHANNEL_ACCESS_EID					0x15
#define EXT_WAVE_WSA_COUNT_TH_INTERVAL				0x16

/******************  WSMP WAVE Element ID  ******************/
#define WSMP_WSM_EID									0x80
#define WSMP_S_EID										0x81
#define WSMP_I_EID										0x82

#define WAVE_EID_LENGTH								1	//WAVE Element ID Length
#define IEEE1609_3_HEADER_LENGTH						4
#define PSID_LENGTH										4
#define WSA_SERVICE_INFO_LENGTH						7
#define PROVIDER_MAC_ADDR_LENGTH						6
#define PROVIDER_MAC_ADDR_FIELD_LENGTH				PROVIDER_MAC_ADDR_LENGTH+2
#define WSA_CHANNEL_INFO_LENGTH						6
#define EDCA_PARAM_SET_LENGTH						20
#define EDCA_PARAM_SET_FIELD_LENGTH					EDCA_PARAM_SET_LENGTH+2
#define WSA_WRA_LENGTH								58			



#define ORGANIZATION_ID_LENGTH			5
#define IEEE1609_0_HEADER_LENGTH			ORGANIZATION_ID_LENGTH   //5


/********************	802.11p  ********************/

#define VS_CATEGORY_LENGTH			1
#define VENDOR_SPECIFIC_CATEGORY	0x7F //127
