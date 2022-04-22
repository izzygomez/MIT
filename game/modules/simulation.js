/**
* Methods that implement the start and stop functionality of 
* the Game of Life simulation
**/

// unique ID to interval, which is a function that calls another function by some frequency
var nIntervId = 0;

var startSimulation = function () {
	// call the firstArg function every secondArg milliseconds
	nIntervId = setInterval(CURRENT_BOARD.step, 500);

	// update status message on front page
	$("#statusmessage").empty();
	$("#statusmessage").append("Running...");

	// disable buttons to avoid bugs
	document.getElementById("stepbutton").disabled = true;
	document.getElementById("startbutton").disabled = true;
	document.getElementById("gliderbutton").disabled = true;
	document.getElementById("pulsarbutton").disabled = true;
	document.getElementById("flowerbutton").disabled = true;
	document.getElementById("blankbutton").disabled = true;
}

var stopSimulation = function () {
	// stop the interval function that was spawned when start started
	clearInterval(nIntervId);

	// update status message on front page
	$("#statusmessage").empty();
	$("#statusmessage").append("Stopped.");

	// re-enable buttons that were disabled during simulation
	document.getElementById("stepbutton").disabled = false;
	document.getElementById("startbutton").disabled = false;
	document.getElementById("gliderbutton").disabled = false;
	document.getElementById("pulsarbutton").disabled = false;
	document.getElementById("flowerbutton").disabled = false;
	document.getElementById("blankbutton").disabled = false;
}