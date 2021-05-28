# Build and Test the Website

You may have noticed that the `markdown` files in the `/docs` directory are also displayed on [Kilo's website](https://kilo.squat.ai/).
If you want to add documentation to Kilo, you can start a local webserver to check out how the website would look like.

## Requirements

Install [yarn](https://yarnpkg.com/getting-started/install).

## Build and Run

The markdown files for the website are located in `/website/docs` and are generated from the like-named markdown files in the `/docs` directory and from the corresponding header files without the `.md` extension in the `/website/docs` directory.
To generate the markdown files in `/website/docs`, run:
```shell
make website/docs/README.md
```

Next, build the website itself by installing the `node_modules` and building the website's HTML from the generated markdown:
```shell
make website/build/index.html
```

Now, start the website server with:
```shell
yarn --cwd website start
```
This command should have opened a browser window with the website; if not, open your browser and point it to `http://localhost:3000`.

If you make changes to any of the markdown files in `/docs` and want to reload the local `node` server, run:
```shell
make website/docs/README.md -B
```

You can execute the above while the node server is running and the website will be rebuilt and reloaded automatically.

## Add a New File to the Docs

If you add a new file to the `/docs` directory, you also need to create a corresponding header file containing the front-matter in `/website/docs/`.
Then, regenerate the markdown for the website with the command:
```shell
make website/docs/README.md
```
Edit `/website/sidebars.js` accordingly.
_Note:_ The `id` in the header file `/website/docs/<new file>` must match the `id` specified in `website/sidebars.js`.
