<?php
/*
 * PHP W3 Log Security Analyser
 * Purpose: Scan W3 Log files for entries that require a server admin to look at.
 * Version: 1.0.0
 * Author: Chaoix
 */
 
//Options
$log_file = '<path to W3 log file>'; //Array of log files to parse for data
$max_line_length = 1024; //Maximum length of lines in file. Lines longer than this will be ignored.
$results_index = 'c-ip'; //Log data fields used to group requests
$debug = false;

//Enforce line_numbers get variable
if( isset($_GET['results']) && empty($_POST) )
	header("Location: ".$_SERVER['PHP_SELF']);

function process_log_file( $filepath ) {
	global $max_line_length, $results_index, 
		$results_order_by, $results_order, $debug;
	
	if ( !is_readable($filepath) ) {
		echo "Error: Unable to open log file: ".$filepath;
		return;
	}
	
	//Open file for reading
	$log_handle = fopen($filepath, 'r');
	
	$fields_hash = false;
	$fields_def = false;
	$fields_count = 0;
	$results = array();
	$log_line_num = 0;
	while ( !feof($log_handle) ) {
		//Get next line in file
		$log_line = fgets($log_handle, $max_line_length);
		$log_line_num++;
		if ( false === $log_line )
			continue;
		
		//Sanitize line
		$log_line = sanitize_log_line($log_line);
		
		//Parse directives
		if ( 0 === stripos($log_line, '#fields') ) {
			//Parse field definitions
			$line_hash = hash('md5', $log_line);
			if ( $line_hash == $fields_hash ) {
				continue; //Same field definitions already being used
			} else {
				$fields_hash = $line_hash;
				$fields_def = preg_split('/\s+/', $log_line);
				array_shift($fields_def); //Remove fields directive from array
				$fields_def = array_flip($fields_def); //Index by field name
				$fields_count = count($fields_def);
				if ( $debug )
					var_dump($fields_def);
			}
		}
		
		//Skip unhandled directives and any data before the fields definition
		if ( '#' == $log_line[0] || empty($fields_def) )
			continue; //Skip line
		
		//Process log data
		$log_line_data = preg_split('/\s+/', $log_line);
		if ( count($log_line_data) != $fields_count )
			continue; //Skip lines that don't match the fields count
		if ( !empty_log_field($log_line_data[$fields_def[$results_index]]) ) {
			$result_index = $log_line_data[$fields_def[$results_index]];
			$results[$result_index][] = $log_line_num;
		}
	}
	
	//Close file
	fclose($log_handle);

	return $results;
}

function output_log_lines( $filepath, $line_nums ) {
	global $max_line_length;
	
	if ( !is_readable($filepath) ) {
		echo "Error: Unable to open log file: ".$filepath;
		return;
	}
	if( empty($line_nums) )
		return;
	
	//Open file for reading
	$log_handle = fopen($filepath, 'r');
	
	sort($line_nums, SORT_NUMERIC);
	reset($line_nums);
	$results = array();
	$log_line_num = 0;
	while ( !feof($log_handle) ) {
		//Get next line in file
		$log_line = fgets($log_handle, $max_line_length);
		$log_line_num++;
		if ( $log_line_num != current($line_nums) )
			continue;
		
		if ( false !== $log_line ) {
			//Sanitize line
			$log_line = sanitize_log_line($log_line);
			//Output the line
			echo '<ol start="'.current($line_nums).'">'."\n";
			echo '<li>'.htmlspecialchars($log_line)."</li>\n";
			echo "</ol>\n";
		}
		
		//Advance the line number list
		$next_line_num = next($line_nums);
		
		if ( false === $next_line_num )
			break; //No more lines to output
	}
	
	//Close file
	fclose($log_handle);
}

function sanitize_log_line( $log_line ) {
	return trim($log_line);
}

function empty_log_field( $log_field ) {
	if( empty($log_field) || '-' == $log_field )
		return true;
	return false;
}
?>
<!DOCTYPE html>
<html>
	<head>
		<title>PHP W3 Log Security Analyser</title>
		<style type="text/css">
			table {
				border-collapse: collapse;
			}
			td, th {
				border: 1px solid black;
				padding: 5px;
			}
		</style>
	</head>
	<body>
		<?php
		if ( !empty($_POST['lines']) ) {
			$line_nums = explode(',', $_POST['lines']);
			output_log_lines($log_file, $line_nums);
		} else {
			//Process each log file specified
			$log_results = array();
			$log_results[] = process_log_file($log_file);
			
			//Output results
			foreach ( $log_results as $log_result ) {
				echo '<table>'."\n";
					echo '<thead>'."\n";
						echo '<tr>'."\n";
							echo '<th>'.$results_index.'</th>'."\n";
							echo '<th>Number of Requests</th>'."\n";
							echo '<th></th>'."\n";
						echo '<tr>'."\n";
					echo '</thead>'."\n";
					foreach( $log_result as $result_index => $result_values) {
						$lines = implode(',', $result_values);
						echo '<tr>'."\n";
							echo '<td>'.$result_index.'</td>'."\n";
							echo '<td>'.count($result_values).'</td>'."\n";
							echo '<td><form action="?results='.time().'&index='.$result_index.'" method="post" target="_blank">'.
								'<input name="lines" type="hidden" value="'.$lines.'" />'.
								'<input name="submit" type="submit" value="Show Requests">'.
								'</form></td>'."\n";
						echo '<tr>'."\n";
					}
				echo '</table>'."\n";
			}
		}
		?>
	</body
</html>
