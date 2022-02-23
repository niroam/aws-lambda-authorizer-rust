#!/bin/bash
# Build Dotnet Core Lambdas
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
reset=$(tput sgr0)

rm -r ./code/target/x86_64-unknown-linux-gnu/release/*.zip
pushd .
cd ./code/
cross build --target x86_64-unknown-linux-gnu --release
popd

goahead=1
currgoahead=1
while read -r fname; do
    filename=${fname##*/}
    path=${fname%/*}
    pushd $path >/dev/null
    
	# if out1=$(find . -iname "bin" -o -iname "obj" | xargs rm -rf 2>&1); then
	# 	echo "$filename ::: $yellow Build folder cleared successfully. $reset"
	# else
	# 	echo "$filename ::: $red Clearing build folders failed. $reset"
	# 	goahead=0
	# 	currgoahead=0
	# fi
	if [ "$currgoahead" -eq "1" ]; then
		if out=$(zip -r9 -j "$path/$filename.zip" $fname 2>&1); then
			echo "running #### echo -e \"@ $filename\n@=bootstrap\" | zipnote -w $path/$filename.zip 2>&1 "
			if out2=$(echo -e "@ $filename\n@=bootstrap" | zipnote -w $path/$filename.zip 2>&1); then
				echo "$filename ::: $green Packaging successful. $reset"
			else
				errortmp=$(echo "$out2")
				echo "$filename ::: $red Packaging Failed!! $reset"
				echo "$filename ::: $red $out2 $reset"
				goahead=0
			fi
		else
			errortmp=$(echo "$out")
			echo "$filename ::: $red Packaging Failed!! $reset"
			echo "$filename ::: $red $out $reset"
			goahead=0
		fi
	fi
	currgoahead=1
    popd >/dev/null
done <<< "$(find $(pwd)/code/target/x86_64-unknown-linux-gnu/release/ -mindepth 1 -maxdepth 1 -type f -name lambda* ! -name "*.*" -print)"

if [ "$goahead" -eq "1" ]; then
	echo "Build completed successfully in $((SECONDS))s"
else
	echo "Build failed $((SECONDS))s"
	exit 1 # terminate and indicate error
fi


