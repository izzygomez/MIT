 /**
 * Create a GameOfLife object
 * @constructor
 * @param {String} w - width of game of life board
 * @param {String} h - height of game of life board
 */
 var GameOfLife = function (width, height) {
	/**
 	* INITIALIZATION
 	**/

	var that = Object.create(GameOfLife.prototype);
	var board;
	var subscribers = [];

	/**
	* Make sure constructor arguments are valid
	**/
	(function() {
		if (typeof(width) !== 'number' || typeof(height) !== 'number') {
			throw new Error("ArgError: GameOfLife() requires *number* arguments to specify dimensions");
		}
	})();

	/**
	* Initializes board of dead cells with appropriate dimensions
	**/
	(function() {
		var b = [];

		for (var i = 0; i < height; i++) {
			b[i] = [];
			for (var j = 0; j < width; j++) {
				b[i][j] = 0;
			}
		}

		board = b;
	})();

	/**
	* PUBLIC FACING FUNCTIONS
	**/

	/**
	* Subscribe to changes to this object
	* @param subscriber a function that is called whenever the board is changed
	* 
	**/
	that.subscribe = function (subscriber) {
		checkSubscriber(subscriber);
		subscribers[0] = subscriber; // This guarantees we only have one subscriber at a time
	}

	/**
	* Flips the value of the cell located at x, y on the board, which is zero-indexed
	* @param {number} x
	* @param {number} y
	**/
	that.switchCell = function (x, y) {
		checkCoordinates(x,y);

		if (board[y][x] === 1) {
			board[y][x] = 0;
		}
		else {
			board[y][x] = 1;
		}

		// update subscribers to object
		publishChanges();
	}

	/**
	* Makes board update cells to next generation according to rules of Conway's
	* Game of Life
	**/
	that.step = function () {
		var new_board = [];
		for (var i = 0; i < height; i++) {
			new_board[i] = [];
			for (var j = 0; j < width; j++) {
				new_board[i][j] = calculateNewState(i, j);
			}
		}
		board = new_board;

		// update subscribers to object
		publishChanges();
	}

	/**
	* Get a deep copy of the board layout
	* @return {2D array} cells are represented as 1 when 'alive'
	* or 0 when 'dead'
	**/
	that.getBoard = function () {
		return board.map(function (arr) {
			return arr.slice();
		});
	};
	
	/**
	* Get the width of the board
	* @return width
	**/
	that.width = function () {return width;};
	
	/**
	* Get the height of the board
	* @return height
	**/
	that.height = function () {return height;};
	
	/**
	* PRIVATE FUNCTIONS
	**/

	/**
	* Checks valid coordinate arguments
	* @throws error if coordinate arguments are not numbers or outside of board dimensions
	**/
	var checkCoordinates = function (x, y) {
		if (typeof(x) !== 'number' || typeof(y) !== 'number') {
			throw new Error("ArgError: Coordinate arguments are not numbers!")
		}

		if (x < 0 || x >= width || y < 0 || y >= height) {
			throw new Error("ArgError: Coordinate arguments larger than board!");
		}
	};

	/**
	* Checks valid function argument
	* @throws error if argument is not a callable object
	**/
	var checkSubscriber = function (subscriber) {
		if (typeof(subscriber) !== 'function') {
			throw new Error("ArgError: subscriber argument not a callable object (e.g. function)");
		}
	};

	/**
	* Publishes changes whenever board is changed by calling all subscriber functions
	**/
	var publishChanges = function () {
		subscribers.forEach(function (subscriptionFunction) {
			subscriptionFunction();
		});
	};

	/**
	* Calculate new state of cell at x, y according to neighbors value (based on Conway's
	* Game of Life rules)
	* @param {number} x
	* @param {number} y
	**/
	var calculateNewState = function (x, y) {
		// compile values of neighboring cells
		var neighbors = [[x-1, y-1], [x, y-1], [x+1, y-1], 
						 [x-1, y],             [x+1, y],
						 [x-1, y+1], [x, y+1], [x+1, y+1]];
		
		var alive_count = 0;

		// check all neighbors
		neighbors.forEach( function (element, index, array) {
			var neighbor_x = element[0]; 
			var neighbor_y = element[1];

			// x, y of neighbor is valid and within board
			if (neighbor_x >= 0 && neighbor_y >= 0 && neighbor_x < width && neighbor_y < height) {
				// count neighbors that are alive
				if (board[neighbor_x][neighbor_y] === 1) {alive_count++;}
			}
		});

		var current_cell_is_alive = (board[x][y] === 1);

		// fit within rule system, and return either 1 or 0 accordingly
		if (current_cell_is_alive && alive_count < 2) {return 0;}
		else if (current_cell_is_alive && (alive_count === 2 || alive_count === 3)) {return 1;}
		else if (current_cell_is_alive && alive_count > 3) {return 0;}
		else if (!current_cell_is_alive && alive_count === 3) {return 1;}
		else {return 0;}
	}

	Object.freeze(that);
	return that;
};