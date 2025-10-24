#! /bin/sh

# set these up in the environment before running this script
# export VERACODE_API_KEY_ID=${{ secrets.VERACODE_API_ID }}
# export VERACODE_API_KEY_SECRET=${{ secrets.VERACODE_API_KEY }}

output_file=flaws_all.json

guid=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v1/applications?name=NodeGoat" | jq -r '._embedded.applications[0].guid') 
echo GUID: ${guid}

total_pages=$(http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&include_annot=true" | tee flaws_p0.json | jq -r '.page.total_pages')
echo Pages: ${total_pages}

if [ ${total_pages} == 1 ]
then
	mv flaws_p0.json ${output_file}
else
	echo Already have flaws, page 0

	# get the rest of the pages and merge flaws
	for (( page=1; page<${total_pages}; page++ ))
	do
		echo Getting flaws, page ${page}
		http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${guid}/findings?scan_type=STATIC&violates_policy=True&include_annot=true&page=${page}" > flaws_tmp.json
		
		echo Merging flaws, page `expr ${page} - 1` into page ${page}
		jq -s '.[0] as $f1 | .[1] as $f2 | ($f1 + $f2) | ._embedded.findings = ($f1._embedded.findings + $f2._embedded.findings)' flaws_p`expr ${page} - 1`.json flaws_tmp.json > flaws_p${page}.json
	done
	
	# rename final output file
	mv flaws_p`expr ${page} - 1`.json ${output_file}
fi

echo Done.  All flaws are in ${output_file}
