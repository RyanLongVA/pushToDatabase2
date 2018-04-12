#!/bin/sh

while [ ! -f $finalLOC ] ;
do
	echo "The merged wordlist that was created from the GoBuster container does not exist yet so waiting.."
	sleep 10
done

if [ -f $finalLOC ];
	then echo "The merged wordlist exists now"
	while [ ! -s $cewltmp ];
		do
			echo "The merged wordlist exists but size is zero"
			sleep 10
		done
	echo "The merged wordlist exists and size is non-zero"
fi

echo "Running my own custom enumall script (https://raw.githubusercontent.com/anshumanbh/domain/master/enumall.py) using recon-ng"
echo "For this, we are using the merged wordlist (W)"
/usr/bin/python /opt/subscan/recon-ng/enumall.py $TARGETS
echo "Saving the Enumall output to combine with the rest later"
if [ ! -f $enumallfile ];
	then echo "enumall did not create the output file --> creating a empty file for script continuation";
	touch $enumallfile;
	echo "Finished"
fi 
