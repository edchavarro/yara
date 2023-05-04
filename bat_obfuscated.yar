rule Obfuscated_bat_FUD{
meta:
	author="Eduardo Chavarro"
	contact="@echavarro on twitter"
	description="More information https://twitter.com/wdormann/status/1651631372438585344"

strings:
	$echo= "@echo off" ascii

	$c1= "%@ech\"" ascii
	$c2= "%exit\"" ascii
	$c3= "\"%~0.\"" ascii
	$c4= "%]::N\"" ascii

	$s1 = {73 65 74 20 [2-5] 3D 73 65 74}
	$s2 = {3D 73 [3-50] 65 74}
	$s3 = {3D 73 65 [3-50] 74}

condition:
  $echo and all of ($c*) and 1 of ($s*)
}