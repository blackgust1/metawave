#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "qdecoder.h"
#include "../../../comm_inc/bsm.h"
#include "../../../comm_inc/svcdefs.h"
#include "../../../comm_inc/asn.h"

#define ONE_BYTE    1
#define TWO_BYTE    2
#define FOUR_BYTE   4
#define EIGHT_BYTE  8

#define BRAKE_BAS   4
#define BRAKE_SIZE  5

#define BUFF_SIZE   1024

static int      count   = 0;
static bsm_t    bsm;

void display_bsm( void )
{
    int i = 0;

    printf( "\n\n------- BasicSafetyMessage ---------\n" );
    printf( "bsm.msgid = %02X\n", bsm.msgid );
    printf( "\nblob1\n");
    
    for( i = 0; i < count; i++ )
    {
        printf( "  bsm.blob1[%d] = %02X\n", i, bsm.blob1[i] );
    }
}

void speed_and_trans( unsigned char * speed, unsigned char * trans )
{
    bsm.blob1[count] = speed[1] + trans[0];
    count++;

    bsm.blob1[count] = speed[0];
    count++;
}

void brake_data( unsigned char **value )
{
    bsm.blob1[count] = *value[0] + *value[1] + *value[2];
    count++;

    bsm.blob1[count] = *value[3] + *value[4];
    count++;
}

void size_converter( unsigned char *width, unsigned char *length )
{
    bsm.blob1[count] = width[1];
    count++;

    bsm.blob1[count] = width[0] + length[1];
    count++;

    bsm.blob1[count] = length[0];
    count++;
}

void bsm_blob_converter( unsigned char * data, int type )
{
    int i       = 0;

    for( i = (type-1); i >= 0; i-- )
    {
        bsm.blob1[count] = data[i];
        count++;
    }
}

int main( int argc, char **argv )
{
    char            *value                  = NULL;
    char            *token                  = NULL;

    int             cnv_value               = 0;
    long            cnv_long                = 0;
    unsigned short  speed                   = 0;
    unsigned char   trans                   = 0;
    unsigned char * sat                     = NULL;

    int             brake[BRAKE_BAS]        = { 0, };
    int             brake_check             = 0;
    unsigned char   brake_sum               = 0;
    unsigned char   brake_tcs               = 0;
    unsigned char   brake_abs               = 0;
    unsigned char   brake_scs               = 0;
    unsigned char   brake_bba               = 0;
    unsigned char * brake_value[BRAKE_SIZE] = { 0, };

    unsigned short  size_width              = 0;
    unsigned short  size_length             = 0;

    qentobj_t       obj;

    char            buff[BUFF_SIZE]         = { 0, };
    size_t          size                    = 0;

    unsigned char   psid[3]                 = { 0, };
    int i = 0;

    /* parse queries. */
    qentry_t *req = qcgireq_parse( NULL, 0 );

    /* debug */
    qcgires_setcontenttype( req, "text/plain" );

    /* get value */
    //-- msgID --//
    value = (char *)req->getstr( req, "msgid", false );
    cnv_value = atoi( value );
    bsm.msgid = (unsigned char)cnv_value;
    
    //-- blob.msgcnt --//
    value = (char *)req->getstr( req, "msgcnt", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, ONE_BYTE );

    //-- blob.id(ip addres) --//
    value = (char *)req->getstr( req, "id", false );
    token = strtok( value, ". " );
    if( token == NULL )
    {
        cnv_value = 0;
        bsm_blob_converter( (unsigned char *)&cnv_value, FOUR_BYTE );
    }
    else
    {
        while( token != NULL )
        {
            cnv_value = atoi( token );
            bsm_blob_converter( (unsigned char *)&cnv_value, ONE_BYTE );
            token = strtok( NULL, ". " );
        }
    }
   
    //-- blob.secmark --//
    value = (char *)req->getstr( req, "secmark", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, TWO_BYTE );
    
    //-- blob.latitude --//
    value = (char *)req->getstr( req, "latitude", false );
    cnv_long = atol( value );
    bsm_blob_converter( (unsigned char *)&cnv_long, FOUR_BYTE );

    //-- blob.longitude --//
    value = (char *)req->getstr( req, "longitude", false );
    cnv_long = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_long, FOUR_BYTE );

    //-- blob.elevation --//
    value = (char *)req->getstr( req, "elevation", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, TWO_BYTE );

    //-- blob.accuracy --//
    value = (char *)req->getstr( req, "major", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, ONE_BYTE );

    value = (char *)req->getstr( req, "minor", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, ONE_BYTE );

    value = (char *)req->getstr( req, "orientation", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, TWO_BYTE );

    //-- blob.speed and transmission --//
    value = (char *)req->getstr( req, "speed", false );
    speed = atoi( value );

    value = (char *)req->getstr( req, "transmission", false );
    trans = atoi( value );

    speed_and_trans( (unsigned char *)&speed, (unsigned char *)&trans );

    //-- blob.heading --//
    value = (char *)req->getstr( req, "heading", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, TWO_BYTE );

    //-- blob.steering wheel --//
    value = (char *)req->getstr( req, "steering", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, ONE_BYTE );


    //-- blob.accel set --//
    value = (char *)req->getstr( req, "longitudinal", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, TWO_BYTE );

    value = (char *)req->getstr( req, "lateral", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, TWO_BYTE );

    value = (char *)req->getstr( req, "vertical", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, ONE_BYTE );

    value = (char *)req->getstr( req, "raw_rate", false );
    cnv_value = atoi( value );
    bsm_blob_converter( (unsigned char *)&cnv_value, TWO_BYTE );

    //-- blob.brake data --//
    memset( (void *)&obj, 0, sizeof( obj ) );
    brake_check = 0;
    brake_sum   = 0;

    while( req->getnext( req, &obj, "checklist_brake", false ) == true )
    {
        brake[brake_check] = atoi( (char *)obj.data );
        brake_sum += brake[brake_check];
        brake_check++;
    }
    brake_value[0] = (unsigned char *)&brake_sum;

    value = (char *)req->getstr( req, "tcs", false );
    brake_tcs = atoi( value );
    brake_value[1] = (unsigned char *)&brake_tcs;

    value = (char *)req->getstr( req, "abs", false );
    brake_abs = atoi( value );
    brake_value[2] = (unsigned char *)&brake_abs;

    value = (char *)req->getstr( req, "scs", false );
    brake_scs = atoi( value );
    brake_value[3] = (unsigned char *)&brake_scs;

    value = (char *)req->getstr( req, "bba", false );
    brake_bba = atoi( value );
    brake_value[4] = (unsigned char *)&brake_bba;

    brake_data( brake_value );

    //-- blob.size width/length --//
    value = (char *)req->getstr( req, "size_width", false );
    size_width = atoi( value ) << 4;

    value = (char *)req->getstr( req, "size_length", false );
    size_length = atoi( value );
    
    size_converter( (unsigned char *)&size_width, (unsigned char *)&size_length );

//    display_bsm();

    size = request_encode( INP_DER, &bsm, buff, BUFF_SIZE );

    printf( "-------------------------------------------------------------------------------\n" );
    printf( "bsm incoding data( %d )\n", size );
    for( i = 0; i < size; i++ )
    {
        if( (i % 16) == 0 ) printf( "\n" );
        printf(" %02x ", buff[i] );
    }
    printf( "\n" );


    psid[0] = 0xC0;
    psid[1] = 0x03;
    psid[2] = 0x05;
    
    WSM_WaveShortMessage_request( psid, buff, size );

//    request_decode( OUT_DER, buff, size );

    /* de-allocate memories */
    req->free( req );

    return 0;
}
