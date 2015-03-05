#ifndef     _BSM_PART2_H_
#define     _BSM_PART2_H_

#define A_SET_OF(type)                      \
    struct {                                \
        type **array;                       \
        int count;  /* Meaningful size */   \
        int size;   /* Allocated size */    \
        void (*free)(type *);               \
    }

#define A_SEQUENCE_OF(type) A_SET_OF(type)

typedef long                                                            BumperHeightFront_t;
typedef long                                                            BumperHeightRear_t;

typedef struct BIT_STRING_s {
    unsigned char                                                       *buf;
    int                                                                 size;

    int                                                                 bits_unused;
} BIT_STRING_t;

typedef struct OCTET_STRING {
    unsigned char                                                       *buf;
    int                                                                 size;
} OCTET_STRING_t;

typedef struct BumperHeights {
    BumperHeightFront_t  frnt;
    BumperHeightRear_t   rear;
} BumperHeights_t;

typedef long                                                            EventFlags_t;

typedef long                                                            DYear_t;
typedef long                                                            DMonth_t;
typedef long                                                            DDay_t;
typedef long                                                            DHour_t;
typedef long                                                            DMinute_t;
typedef long                                                            DSecond_t;

typedef long                                                            Longitude_t;
typedef long                                                            Latitude_t;
typedef OCTET_STRING_t                                                  Elevation_t;
typedef long                                                            Heading_t;
typedef OCTET_STRING_t                                                  TransmissionAndSpeed_t;
typedef OCTET_STRING_t                                                  PositionalAccuracy_t;
typedef long                                                            TimeConfidence_t;
typedef OCTET_STRING_t                                                  PositionConfidenceSet_t;
typedef OCTET_STRING_t                                                  SpeedandHeadingandThrottleConfidence_t;

typedef BIT_STRING_t                                                    GPSstatus_t;
typedef long                                                            Count_t;

typedef OCTET_STRING_t                                                  RTCMHeader_t;

typedef long                                                            ExteriorLights_t;
typedef long                                                            LightbarInUse_t;
typedef OCTET_STRING_t                                                  BrakeSystemStatus_t;
typedef long                                                            BrakeAppliedPressure_t;
typedef long                                                            CoefficientOfFriction_t;
typedef long                                                            SunSensor_t;
typedef long                                                            RainSensor_t;
typedef long                                                            AmbientAirTemperature_t;
typedef long                                                            AmbientAirPressure_t;
typedef long                                                            ThrottlePosition_t;
typedef long                                                            SpeedConfidence_t;
typedef long                                                            WiperStatusFront_t;
typedef long                                                            WiperRate_t;
typedef long                                                            WiperStatusRear_t;
typedef OCTET_STRING_t                                                  SteeringWheelAngle_t;
typedef long                                                            SteeringWheelAngleConfidence_t;
typedef long                                                            SteeringWheelAngleRateOfChange_t;
typedef long                                                            DrivingWheelAngle_t;
typedef OCTET_STRING_t                                                  AccelerationSet4Way_t;
typedef BIT_STRING_t                                                    VerticalAccelerationThreshold_t;
typedef long                                                            YawRateConfidence_t;
typedef long                                                            AccelerationConfidence_t;
typedef long                                                            ObstacleDistance_t;
typedef Heading_t                                                       ObstacleDirection_t;
typedef long                                                            VehicleHeight_t;
typedef long                                                            VehicleMass_t;
typedef long                                                            TrailerWeight_t;
typedef long                                                            VehicleType_t;
typedef long                                                            EssPrecipYesNo_t;
typedef long                                                            EssPrecipRate_t;
typedef long                                                            EssPrecipSituation_t;
typedef long                                                            EssSolarRadiation_t;
typedef long                                                            EssMobileFriction_t;

typedef OCTET_STRING_t                                                  IA5String_t;                    /* Implemented via OCTET STRING */
typedef IA5String_t                                                     DescriptiveName_t;
typedef OCTET_STRING_t                                                  VINstring_t;
typedef OCTET_STRING_t                                                  TemporaryID_t;
typedef long                                                            VehicleType_t;
typedef long                                                            VehicleGroupAffected_t;
typedef long                                                            ResponderGroupAffected_t;
typedef long                                                            IncidentResponseEquipment_t;

typedef long                                                            CargoWeight_t;
typedef long                                                            SteeringAxleTemperature_t;
typedef long                                                            DriveAxleLocation_t;
typedef long                                                            DriveAxleLiftAirPressure_t;
typedef long                                                            DriveAxleTemperature_t;
typedef long                                                            DriveAxleLubePressure_t;
typedef long                                                            SteeringAxleLubePressure_t;
typedef long                                                            TireLocation_t;
typedef long                                                            TirePressure_t;
typedef long                                                            TireTemp_t;
typedef long                                                            WheelSensorStatus_t;
typedef BIT_STRING_t                                                    WheelEndElectFault_t;
typedef long                                                            TireLeakageRate_t;
typedef long                                                            TirePressureThresholdDetection_t;
typedef long                                                            AxleLocation_t;
typedef long                                                            AxleWeight_t;

typedef long                                                            ThrottleConfidence_t;


typedef struct DDateTime {
    DYear_t                                                             *year;                          // OPTIONAL
    DMonth_t                                                            *month;                         // OPTIONAL
    DDay_t                                                              *day;                           // OPTIONAL
    DHour_t                                                             *hour;                          // OPTIONAL
    DMinute_t                                                           *minute;                        // OPTIONAL
    DSecond_t                                                           *second;                        // OPTIONAL
} DDateTime_t;


typedef struct FullPositionVector {
    struct DDateTime                                                    *utcTime;                       // OPTIONAL
    Longitude_t                                                         Long;
    Latitude_t                                                          lat;
    Elevation_t                                                         *elevation;                     // OPTIONAL
    Heading_t                                                           *heading;                       // OPTIONAL
    TransmissionAndSpeed_t                                              *speed;                         // OPTIONAL
    PositionalAccuracy_t                                                *posAccuracy;                   // OPTIONAL
    TimeConfidence_t                                                    *timeConfidence;                // OPTIONAL
    PositionConfidenceSet_t                                             *posConfidence;                 // OPTIONAL
    SpeedandHeadingandThrottleConfidence_t                              *speedConfidence;               // OPTIONAL
} FullPositionVector_t;


typedef enum PathHistory__crumbData_PR {
    PathHistory__crumbData_PR_NOTHING,  /* No components present */
    PathHistory__crumbData_PR_pathHistoryPointSets_01,
    PathHistory__crumbData_PR_pathHistoryPointSets_02,
    PathHistory__crumbData_PR_pathHistoryPointSets_03,
    PathHistory__crumbData_PR_pathHistoryPointSets_04,
    PathHistory__crumbData_PR_pathHistoryPointSets_05,
    PathHistory__crumbData_PR_pathHistoryPointSets_06,
    PathHistory__crumbData_PR_pathHistoryPointSets_07,
    PathHistory__crumbData_PR_pathHistoryPointSets_08,
    PathHistory__crumbData_PR_pathHistoryPointSets_09,
    PathHistory__crumbData_PR_pathHistoryPointSets_10
} PathHistory__crumbData_PR;


typedef struct PathHistoryPointType_01 {
    long                                                                latOffset;
    long                                                                longOffset;
    long                                                                *elevationOffset;               // OPTIONAL
    long                                                                *timeOffset;                    // OPTIONAL
    PositionalAccuracy_t                                                *posAccuracy;                   // OPTIONAL
    long                                                                *heading;                       // OPTIONAL
    TransmissionAndSpeed_t                                              *speed;                         // OPTIONAL
} PathHistoryPointType_01_t;

typedef struct PathHistory {
    struct FullPositionVector                                           *initialPosition;               // OPTIONAL
    GPSstatus_t                                                         *currGPSstatus;                 // OPTIONAL
    Count_t                                                             *itemCnt;                       // OPTIONAL
    struct PathHistory__crumbData {
        PathHistory__crumbData_PR                                       present;
        union PathHistory__crumbData_u {
            struct PathHistory__crumbData__pathHistoryPointSets_01 {
                A_SEQUENCE_OF(struct PathHistoryPointType_01)           list;
            } pathHistoryPointSets_01;
            OCTET_STRING_t                                              pathHistoryPointSets_02;
            OCTET_STRING_t                                              pathHistoryPointSets_03;
            OCTET_STRING_t                                              pathHistoryPointSets_04;
            OCTET_STRING_t                                              pathHistoryPointSets_05;
            OCTET_STRING_t                                              pathHistoryPointSets_06;
            OCTET_STRING_t                                              pathHistoryPointSets_07;
            OCTET_STRING_t                                              pathHistoryPointSets_08;
            OCTET_STRING_t                                              pathHistoryPointSets_09;
            OCTET_STRING_t                                              pathHistoryPointSets_10;
        } choice;
    } crumData;
} PathHistory_t;


typedef struct PathPrediction {
    long                                                                radiusOfCurve;
    long                                                                confidence;
} PathPrediction_t;


typedef struct RTCMPackage {
    struct FullPositionVector                                           *anchorPoint;                   // OPTIONAL
    RTCMHeader_t                                                        rtcmHeader;

    OCTET_STRING_t                                                      *msg1001;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1002;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1003;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1004;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1005;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1006;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1007;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1008;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1009;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1010;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1011;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1012;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1013;                       // OPTIONAL

    OCTET_STRING_t                                                      *msg1014;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1015;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1016;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1017;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1018;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1019;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1020;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1021;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1022;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1023;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1024;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1025;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1026;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1027;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1028;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1029;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1030;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1031;                       // OPTIONAL
    OCTET_STRING_t                                                      *msg1032;                       // OPTIONAL
} RTCMPackage_t;


typedef struct VehicleSafetyExtension {
    EventFlags_t                                                        *events;                        // OPTIONAL
    struct PathHistory                                                  *pathHistory;                   // OPTIONAL
    struct PathPrediction                                               *pathPrediction;                // OPTIONAL
    struct RTCMPackage                                                  *theRTCM;                       // OPTIONAL
} VehicleSafetyExtension_t;

typedef enum VehicleIdent__vehicleClass_PR {
    VehicleIdent__vehicleClass_PR_NOTHING,  /* No components present */
    VehicleIdent__vehicleClass_PR_vGroup,
    VehicleIdent__vehicleClass_PR_rGroup,
    VehicleIdent__vehicleClass_PR_rEquip
} VehicleIdent__vehicleClass_PR;

typedef struct VehicleIdent {
    DescriptiveName_t                                                   *name;                          // OPTIONAL
    VINstring_t                                                         *vin;                           // OPTIONAL
    IA5String_t                                                         *ownerCode;                     // OPTIONAL
    TemporaryID_t                                                       *id;                            // OPTIONAL
    VehicleType_t                                                       *vehicleType;                   // OPTIONAL

    struct VehicleIdent__vehicleClass {
        VehicleIdent__vehicleClass_PR                                   present;
        union VehicleIdent__vehicleClass_u {
            VehicleGroupAffected_t                                      vGroup;
            ResponderGroupAffected_t                                    rGroup;
            IncidentResponseEquipment_t                                 rEquip;
        } choice;
    } *vehicleClass;
} VehicleIdent_t;


typedef struct J1939data {
    struct J1939data__tires {
        A_SEQUENCE_OF(struct J1939data__tires__Member {
            TireLocation_t                                              *location;                      // OPTIONAL
            TirePressure_t                                              *pressure;                      // OPTIONAL
            TireTemp_t                                                  *temp;                          // OPTIONAL
            WheelSensorStatus_t                                         *wheelSensorStatus;             // OPTIONAL
            WheelEndElectFault_t                                        *wheelEndElectFault;            // OPTIONAL
            TireLeakageRate_t                                           *leakageRate;                   // OPTIONAL
            TirePressureThresholdDetection_t                            *detection;                     // OPTIONAL
        } ) list;
    } *tires;

    struct J1939data__axle {
        A_SEQUENCE_OF(struct J1939data__axle__Member {
            AxleLocation_t                                              *location;                      // OPTIONAL
            AxleWeight_t                                                *weight;                        // OPTIONAL
        } ) list;
    } *axle;

    TrailerWeight_t                                                     *trailerWeight;                 // OPTIONAL
    CargoWeight_t                                                       *cargoWeight;                   // OPTIONAL
    SteeringAxleTemperature_t                                           *steeringAxleTemperature;       // OPTIONAL
    DriveAxleLocation_t                                                 *driveAxleLocation;             // OPTIONAL
    DriveAxleLiftAirPressure_t                                          *driveAxleLiftAirPressure;      // OPTIONAL
    DriveAxleTemperature_t                                              *driveAxleTemperature;          // OPTIONAL
    DriveAxleLubePressure_t                                             *driveAxleLubePressure;         // OPTIONAL
    SteeringAxleLubePressure_t                                          *steeringAxleLubePressure;      // OPTIONAL
} J1989data_t;


typedef struct AccelSteerYawRateConfidence {
    YawRateConfidence_t                                                 yawRate;
    AccelerationConfidence_t                                            acceleration;
    SteeringWheelAngleConfidence_t                                      steeringWheelAngle;
} AccelSteerYawRateConfidence_t;


typedef struct ConfidenceSet {
    struct AccelSteerYawRateConfidence                                  *accelConfidence;               // OPTIONAL
    SpeedandHeadingandThrottleConfidence_t                              *speedConfidence;               // OPTIONAL
    TimeConfidence_t                                                    *timeConfidence;                // OPTIONAL
    PositionConfidenceSet_t                                             *posConfidence;                 // OPTIONAL
    SteeringWheelAngleConfidence_t                                      *steerConfidence;               // OPTIONAL
    ThrottleConfidence_t                                                *throttleConfidence;            // OPTIONAL
} ConfidenceSet_t;


typedef struct VehicleStatus {
    ExteriorLights_t                                                    *lights;                        // OPTIONAL
    LightbarInUse_t                                                     *lightBar;                      // OPTIONAL

    struct VehicleStatus__wipers {
        WiperStatusFront_t                                              statusFront;
        WiperRate_t                                                     rateFront;
        WiperStatusRear_t                                               *statusRear;                    // OPTIONAL
        WiperRate_t                                                     *rateRear;                      // OPTIONAL
    } *wipers;

    BrakeSystemStatus_t                                                 *brakeStatus;                   // OPTIONAL
    BrakeAppliedPressure_t                                              *brakePressure;                 // OPTIONAL
    CoefficientOfFriction_t                                             *roadFriction;                  // OPTIONAL
    SunSensor_t                                                         *sunData;                       // OPTIONAL
    RainSensor_t                                                        *rainData;                      // OPTIONAL
    AmbientAirTemperature_t                                             *airTemp;                       // OPTIONAL
    AmbientAirPressure_t                                                *airPres;                       // OPTIONAL

    struct VehicleStatus__steering {
        SteeringWheelAngle_t                                            angle;
        SteeringWheelAngleConfidence_t                                  *confidence;                    // OPTIONAL
        SteeringWheelAngleRateOfChange_t                                *rate;                          // OPTIONAL
        DrivingWheelAngle_t                                             *wheels;                        // OPTIONAL
    } *steering;

    struct VehicleStatus__accelSets {
        AccelerationSet4Way_t                                           *accel4way;                     // OPTIONAL
        VerticalAccelerationThreshold_t                                 *vertAccelThres;                // OPTIONAL
        YawRateConfidence_t                                             *yawRateCon;                    // OPTIONAL
        AccelerationConfidence_t                                        *hozAccelCon;                   // OPTIONAL
        struct ConfidenceSet                                            *confidenceSet;                 // OPTIONAL
    } *accelSets;

    struct VehicleStatus__object {
        ObstacleDistance_t                                              obDist;
        ObstacleDirection_t                                             obDirect;
        DDateTime_t                                                     dateTime;
    } *object;

    struct FullPositionVector                                           *fullPos;                       // OPTIONAL
    ThrottlePosition_t                                                  *throttlePos;                   // OPTIONAL
    SpeedandHeadingandThrottleConfidence_t                              *speedHeadC;                    // OPTIONAL
    SpeedConfidence_t                                                   *speedC;                        // OPTIONAL

    struct VehicleStatus__vehicleData {
        VehicleHeight_t                                                 height;
        BumperHeights_t                                                 bumpers;
        VehicleMass_t                                                   mass;
        TrailerWeight_t                                                 trailerWeight;
        VehicleType_t                                                   type;
    } *vehicleData;

    struct VehicleIdent                                                 *vehicleIdent;                  // OPTIONAL
    struct J1939data                                                    *j1939data;                     // OPTIONAL
    
    struct VehicleStatus__weatherReport {
        EssPrecipYesNo_t                                                isRaining;
        EssPrecipRate_t                                                 *rainRate;                      // OPTIONAL
        EssPrecipSituation_t                                            *precipSituation;               // OPTIONAL
        EssSolarRadiation_t                                             *solarRadiation;                // OPTIONAL
        EssMobileFriction_t                                             *friction;                      // OPTIONAL
    } *weatherReport;

    GPSstatus_t                                                         *gpsStatus;                     // OPTIONAL
} VehicleStatus_t;


typedef struct BasicSafetyMessage {
    struct VehicleSafetyExtension                                       *safetyExt;
    struct VehicleStatus                                                *status;
} BasicSafetyMessage_t;

#endif  /* _BSM_PART2_H_ */
