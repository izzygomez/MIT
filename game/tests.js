QUnit.test( "hello test", function( assert ) {
	var board = GameOfLife(10,10);
	assert.ok( board.getBoard()[0][0] === "0", "Passed!" );
});