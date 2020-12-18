# cstrnfinder

A Binary Ninja plugin to help uncover potentially faulty string compares. Based on the idea of [@disconnect3d_pl](https://twitter.com/disconnect3d_pl/). For further information about the idea take a look at the @disconnect3d_pl's [slides](https://docs.google.com/presentation/d/1VpXqzPIPrfIPSIiua5ClNkjKAzM3uKlyAKUf0jBqoUI/edit#slide=id.g70c6018123_0_12) oder [presentation](ttps://youtu.be/-xVBd8MGlJs?t=192). 

## Example

![Example Output](https://github.com/murx-/cstrnfinder/blob/master/img/screenshot.png?raw=true)

## Limitations

Currently only constant strings i.e. residing in `.rodata` are checked. This means if the value is compared against a constant variable on the stack this is currently not checked. 