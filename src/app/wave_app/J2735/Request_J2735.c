#include <stdio.h>
#include <sys/types.h>

#include <asn_application.h>
#include <asn_internal.h>

#include "BasicSafetyMessage.h"
#include "VehicleSafetyExtension.h"
#include "VehicleStatus.h"
#include "PathHistory.h"

#include "../comm_inc/asn.h"
#include "../comm_inc/bsm.h"

const char  *filename   = "bsm";
FILE        *fp         = NULL;

static int write_out( const void *buffer, size_t size, void *app_key )
{
    FILE *out_fp = app_key;
    size_t wrote = fwrite( buffer, 1, size, out_fp );
    return ( wrote == size ) ? 0 : -1;
}

int request_encode( int type, void* data, char *buf, int size )
{
    BasicSafetyMessage_t    *bsm;
    asn_enc_rval_t          ec;

    bsm_t                   bsm_value;
    size_t                  buf_size;

    bsm = calloc( 1, sizeof( BasicSafetyMessage_t ) );
    if( !bsm )
    {
        perror( "calloc() failed" );
        exit( 1 );
    }

    fp = fopen( filename, "wb" );
    if( !fp )
    {
        perror( filename );
        exit( 1 );
    }

    bsm_value       = *(bsm_t *)data;

    /*
     *  BSM Message
     */ 
    bsm->msgID      = bsm_value.msgid;

    bsm->blob1.buf  = bsm_value.blob1;
    bsm->blob1.size = sizeof( bsm_value.blob1 );

    bsm->safetyExt  = malloc( sizeof(struct VehicleSafetyExtension) );
    bsm->status     = malloc( sizeof(struct VehicleStatus) );

    switch( type )
    {
    case INP_BER:   break;

    case INP_DER:   ec = der_encode( &asn_DEF_BasicSafetyMessage, bsm, write_out, fp );
                    if( ec.encoded == -1 )
                    {
                        fprintf( stderr, "Could not encode bsm (at %s\n", ec.failed_type ? ec.failed_type->name : "unknown" );
                        exit( 1 );
                    }
                    
                    break;

    case INP_PER:   break;


    default:        break;
    }

    fclose( fp );

    fp = fopen( filename, "rb" );
    if( !fp )
    {
        perror( filename );
        exit( 1 );
    }

    buf_size = fread( buf, 1, size, fp );
    if( !buf_size )
    {
        fprintf( stderr, "%s: Empty or broken\n", filename );
        exit( 1 );
    }

    fclose( fp );

    printf( "\n !!!----------------------------------- request_encode() printf message -----------------------------------!!! \n" );
    xer_fprint( stdout, &asn_DEF_BasicSafetyMessage, bsm );

    if( bsm->safetyExt != NULL ){  printf(" free bsm->safetyExt\n" ); free( bsm->safetyExt );  }
    if( bsm->status != NULL ){      printf(" free bsm->status\n" ); free( bsm->status );        }

    return buf_size;
}

int request_decode( int type, char *buf, size_t size )
{
    asn_dec_rval_t          rval;
    BasicSafetyMessage_t    *bsm    = 0;

    switch( type )
    {
    case OUT_BER:   break;

    case OUT_DER:   rval = ber_decode( 0, &asn_DEF_BasicSafetyMessage, (void **)&bsm, buf, size );
                    if( rval.code != RC_OK )
                    {
                        fprintf( stderr, "%s: Broken BSM encoding at byte %ld\n", filename, (long)rval.consumed );
                        exit( 1 );
                    }

                    break;

    case OUT_PER:   break;

    default:        break;
    }

    printf( "\n !!!----------------------------------- request_decode() printf message -----------------------------------!!! \n" );
    xer_fprint( stdout, &asn_DEF_BasicSafetyMessage, bsm );
    return 0;
}
