proj2
=====
Questions copy-paste:
 (a) what concerns you identified, and how you separated them; (b) what the program modules are, what their dependences are on one another, and whether there are any dependences that should ideally be eliminated; (c) how you exploited functionals in your code; (d) any interesting design ideas you had or tradeoffs that you made.

Answers:
 A. The concerns that I identified in implementing the browser-based Game of Life were representing a Game of Life board, displaying it on the page, and running a simulation. I thus separated this functionality into the files gameoflife.js, displayboard.js, and simulation.js, respectively.

 B. The program modules can be thought to be the aforementioned: a board, the display mechanism, and the simulation mechanism. For practical purposes, there's only dependences from the display mechanism to the board (i.e. display mechanism depends on functionality expressed in the board implementation) and from the simulation mechanism to the board. This dependency tree greatly simplifies debugging. There is a small dependency that exists that isn't ideal: in gameoflife.js, there's a design choice to always keep only one subscriber, which is done to reduce the overhead of subscribers that are updated as we modify the boards. I guess the design choice could be justified and be deemed rational without a reference to it's real dependence on the displayboard implementation, but I would be a liar.

 C. I made use of functionals by in various parts of the code. For example, *.forEach is used a couple times in gameoflife.js to iterate over an iterable, such as the array of neighbors to a cell when calculating the next state of a cell.

 D. my tradeoff was not doing tests because I was running out of time :(