#!/bin/bash

echo ""
echo "!!!------------------------------ J2735 make ------------------------------!!!"
cd ./J2735
make
cd ..

echo ""
echo "!!!------------------------------ rsmgmt make ------------------------------!!!"
cd ./rsmgmt
make
cd ..

echo ""
echo "!!!------------------------------ svcmgmt make ------------------------------!!!"
cd ./svcmgmt
make
cd ..

echo ""
echo "!!!------------------------------ wavecmd make ------------------------------!!!"
cd ./wavecmd
make
cd ..

echo ""
echo "!!!------------------------------ cgi make ------------------------------!!!"
cd ./webpage/cgi/bsm
make
cd ../../../

echo ""
echo "!!!------------------------------ wsm make ------------------------------!!!"
cd ./wsm
make
cd ../

