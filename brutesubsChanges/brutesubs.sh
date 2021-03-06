if [ $# -eq 0 ]; then
    echo "No arguments provided. Please provide a domain followed by an output directory like so:"
    echo "./brutesubs tesla.com tesla_output"
    exit 1
fi

domain=$1
save_folder=$2

#mkdir $2
#cp -a . $2
#cd $2
rm .env

echo "TARGETS=$domain
DIRNAME=$save_folder

finalLOC=/data/subnames.txt
gobusterthreads=100
sublist3rthreads=50
altdnsthreads=100

wordlists=all.txt,namelist.txt

temp1=/data/output/temp1.txt
temp2=/data/output/temp2.txt
temp3=/data/output/temp3.txt

gobusterfile=/data/output/gobusteroutput.txt
enumallfile=/data/output/enumalloutput.txt
sublist3rfile=/data/output/sublist3routput.txt

google_api=<>
google_cse=<>
shodan_api=<>

altdnsserver=8.8.8.8

finaloutputbeforealtdns=/data/finaloutputbeforealtdns.txt

altdnsoutput=/data/altdnsoutput.txt
altdnsonlysubs=/data/altdnsonlysubs.txt

final=/data/realfinalresult.txt
finaloutputafteraltdns=/data/finalresult.txt" > .env
#Making the session stick because goBuster might take time
echo "Note: May fail/act weird if connected to vpn\n\nIt seems docker doesn't like it when our internet setup is a little bit wack"
echo "Starting on $domain"
docker-compose up
#sudo docker-compose --verbose up

echo "Docker scripts finished"
sudo chown -R $USER:$USER myoutdir/$save_folder
#Let's just see if go all.txt works

#./massdns/bin/massdns -r massdns/resolvers.txt -t A -a -o -w ./myoutdir/$save_folder/massdnsOut1.txt ./myoutdir/$save_folder/finalresult.txt
#./massdns/bin/massdns -r massdns/resolvers.txt -t A -a -o -w ./myoutdir/$save_folder/massdnsOut2.txt ./myoutdir/$save_folder/finalresult.txt
#sort -u ./myoutdir/$save_folder/massdnsOut1.txt ./myoutdir/$save_folder/massdnsOut2.txt | grep $domain > ./myoutdir/$save_folder/massTemp.txt
#./massdns/bin/massdns -r massdns/resolvers.tdt -t A -a -o -w ./myoutdir/$save_folder/massdnsOut3.txt ./myoutdir/$save_folder/finaloutputbeforealtdns.txt
#sort -u ./myoutdir/$save_folder/massndOut3.txt ./myoutdir/$save_folder | grep $domain > ./myoutdir/massdnsFinal.txt
#echo "--> massdns complete <--"
#cd ./myoutdir/$save_folder/
#python ../../scripts/massdnsToHttpscreen.py -m massdnsOut.txt -o massUrls.txt
#mkdir screenshots; cd screenshots
#echo "--> formatting before screenshots complete <--"
#python ../../../httpscreenshot-master/httpscreenshot.py -l ../massUrls.txt -p -v -vH -tG -sF -t 15 -r 2 -w 10
#cd ..

#echo "Starting manual inspection using -- cat massUrls.txt | grep "$domain" > visualdata.txt"
#echo "You can quit and look at the screenshot/ directory if you want" 
#echo "This is just a trial idea for a quick and more thorough inspection"
#cat massUrls.txt | grep "$domain" > visualData.txt
#python ../../scripts/

#altdns.py to masscan : disable if on bad wifi
#sh bash/altToMassOut.sh $1 $2
