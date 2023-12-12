BEGIN           {
                    # no filter arg make it unmatchable so search works
					if (! filter_arg) {
						filter_arg="lkjr32adfa90u3rjka"
					}
					if (! myip_arg) {
						print "Syntax: must supply desired destination IP with -v myip_arg=\"destination ip address\""
						exit 1
					}
                }
$0 ~ /filter_arg/ { 
					#
					# if we pass value as filter_arg, if it's in the line
					# skip this line!
					#

                    next 
                }     

$0 ~ /IP/       {    # Match lines with "IP". Known syntax.

                    for(i=1; i<NF; i++ ) {
                        if ( $i ~ /IP/) {
							matchsrc=$(i+1)
                            if ( match(matchsrc, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
                                src=substr(matchsrc, RSTART, RLENGTH)
                                }
							matchdst=$(i+3)
							if ( match(matchdst, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
								dst=substr(matchdst, RSTART, RLENGTH)
								}

                            }
							if (dst==myip_arg) {
								print "Date:", $1 , "Time:", $2, "source:", src
							}

						}


                }

