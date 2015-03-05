#!/bin/bash

echo ""
echo "!!!------------------------------ J2735 make clean -------------------------------!!!"
cd ./J2735
make clean
cd ..

echo ""
echo "!!!------------------------------ rsmgmt make clean -------------------------------!!!"
cd ./rsmgmt
make clean
cd ..

echo ""
echo "!!!------------------------------ svcmgmt make clean -------------------------------!!!"
cd ./svcmgmt
make clean
cd ..

echo ""
echo "!!!------------------------------ wavecmd make clean -------------------------------!!!"
cd ./wavecmd
make clean
cd ..

echo ""
echo "!!!------------------------------ cgi make clean -------------------------------!!!"
cd ./webpage/cgi/bsm
make clean
cd ../../../

echo ""
echo "!!!------------------------------ wsm make clean -------------------------------!!!"
cd ./wsm/
make clean
cd ../


