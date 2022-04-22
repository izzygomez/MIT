/**
* Collection of preset Game of Life boards
**/

var gliderBoard = function () {
	var x = GameOfLife(30,30);
	x.switchCell(1,0);
	x.switchCell(2,1);
	x.switchCell(0,2);
	x.switchCell(1,2);
	x.switchCell(2,2);
	return x;
};

var pulsarBoard = function () {
	var x = GameOfLife(30,30);
	x.switchCell(3,1);
	x.switchCell(4,1);
	x.switchCell(5,1);
	x.switchCell(9,1);
	x.switchCell(10,1);
	x.switchCell(11,1);
	x.switchCell(1,3);
	x.switchCell(1,4);
	x.switchCell(1,5);
	x.switchCell(6,3);
	x.switchCell(6,4);
	x.switchCell(6,5);
	x.switchCell(8,3);
	x.switchCell(8,4);
	x.switchCell(8,5);
	x.switchCell(13,3);
	x.switchCell(13,4);
	x.switchCell(13,5);
	x.switchCell(3,6);
	x.switchCell(4,6);
	x.switchCell(5,6);
	x.switchCell(9,6);
	x.switchCell(10,6);
	x.switchCell(11,6);
	x.switchCell(3,8);
	x.switchCell(4,8);
	x.switchCell(5,8);
	x.switchCell(9,8);
	x.switchCell(10,8);
	x.switchCell(11,8);
	x.switchCell(1,9);
	x.switchCell(1,10);
	x.switchCell(1,11);
	x.switchCell(6,9);
	x.switchCell(6,10);
	x.switchCell(6,11);
	x.switchCell(8,9);
	x.switchCell(8,10);
	x.switchCell(8,11);
	x.switchCell(13,9);
	x.switchCell(13,10);
	x.switchCell(13,11);
	x.switchCell(3,13);
	x.switchCell(4,13);
	x.switchCell(5,13);
	x.switchCell(9,13);
	x.switchCell(10,13);
	x.switchCell(11,13);
	return x;
};

var flowerBoard = function () {
	var x = GameOfLife(30,30);
	x.switchCell(6,5);
	x.switchCell(7,5);
	x.switchCell(8,5);
	x.switchCell(5,6);
	x.switchCell(9,6);
	x.switchCell(4,7);
	x.switchCell(10,7);
	x.switchCell(5,8);
	x.switchCell(9,8);
	x.switchCell(6,9);
	x.switchCell(7,9);
	x.switchCell(8,9);
	return x;
};

var blankBoard = function () {
	var x = GameOfLife(30,30);
	return x;
};

var CURRENT_BOARD = blankBoard(); // default board to show when page first loads

/**
* Initialize default board
**/
displayBoard($("#game_board"), CURRENT_BOARD);