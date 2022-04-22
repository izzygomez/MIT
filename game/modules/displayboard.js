/**
 * Install a Game of Life Board in the specified DOM container. A Game of Life 
 * Board is a user interface for editing the game of life board.
 *
 * @param domContainer a jQuery wrapper around a single empty div element to
 *        install the board in.
 * @param {GameOfLife} gameoflife the GameOfLife object to use as a model for the
 *        game being displayed and edited by this widget.
 */
var displayBoard = function(domContainer, gameoflife) {

  var buildAndDisplayBoard = function () {
    // empty DOM container
    domContainer.empty();

    // Construct UI of board using click-sensitive *.png files
    $.each(gameoflife.getBoard(), function (index, value) {
      var rowDivElm = $("<div class='board_row'>");

      $.each(value, function (index2, value2) {
        var cell_image = 'ERROR'; // if ERROR prints, something went wrong

        // add correct image representation depending on whether cell is alive or dead
        if ( value2 === 0 ) {
          cell_image = '<img src="images/dead.png" style="float:left;" onclick="CURRENT_BOARD.switchCell(' + index2 + ',' + index + ');">';
        }
        else if ( value2 === 1 ) {
          cell_image = '<img src="images/alive.png" style="float:left;" onclick="CURRENT_BOARD.switchCell(' + index2 + ',' + index + ');">';
        }

        rowDivElm.append(cell_image);
      });

      domContainer.append(rowDivElm);
    });
  }

  buildAndDisplayBoard();

  /**
  * Subscribe to changes in GameOfLife board; when changes are made, 
  * the board UI will be refreshed by buildAndDisplayBoard()
  **/
  gameoflife.subscribe( function() { buildAndDisplayBoard(); } );
}