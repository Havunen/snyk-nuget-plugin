import * as JSZip from 'jszip';
import * as fs from 'fs';
import * as path from 'path';
import * as parseXML from 'xml2js';
import * as dependency from './dependency';
import * as debugModule from 'debug';
const debug = debugModule('snyk');

const targetFrameworkRegex = /([.a-zA-Z]+)([.0-9]+)/;

async function loadNuspecFromAsync(dep) {
  const nupkgPath = path.resolve(
    dep.path,
    dep.name + '.' + dep.version + '.nupkg',
  );

  //just in case, does the code expect null to be returned on any error here?
  if (fs.existsSync(nupkgPath) === false) return null;

  const nupkgData = fs.readFileSync(nupkgPath);
  const nuspecZipData: any = await JSZip.loadAsync(nupkgData);

  const nuspecFiles = Object.keys(nuspecZipData.files).filter(file => {
    return path.extname(file) === '.nuspec';
  });

  if (!nuspecFiles || !nuspecZipData) {
    //sanity check, perhaps log a warning here?
    return null;
  }

  const nuspecContent = await nuspecZipData.files[nuspecFiles[0]].async('text');
  return nuspecContent;
}

export async function actuallyParsedNuspec(
  nuspecContent: any,
  targetFramework,
  depname,
) {
  const result = await parseXML.parseStringPromise(nuspecContent);
  let ownDeps: any = [];
  // We are only going to check the first targetFramework we encounter
  // in the future we may want to support multiple, but only once
  // we have dependency version conflict resolution implemented
  if (!result.package?.metadata) {
    throw new Error(
      'This is an invalid nuspec file. Metadata xml section is missing. This is a required element. See https://docs.microsoft.com/en-us/nuget/reference/nuspec',
    );
  }
  result.package.metadata.forEach(metadata => {
    if (metadata && metadata.dependencies) {
      metadata.dependencies.forEach(rawDependency => {
        // Find and add target framework version specific dependencies
        const depsForTargetFramework = extractDepsForTargetFramework(
          rawDependency,
          targetFramework,
        );

        if (depsForTargetFramework && depsForTargetFramework.group) {
          ownDeps = ownDeps.concat(
            extractDepsFromRaw(depsForTargetFramework.group.dependency),
          );
        }

        // Find all groups with no targetFramework attribute
        // add their deps
        const depsFromPlainGroups = extractDepsForPlainGroups(rawDependency);

        if (depsFromPlainGroups) {
          depsFromPlainGroups.forEach(depGroup => {
            ownDeps = ownDeps.concat(extractDepsFromRaw(depGroup.dependency));
          });
        }

        // Add the default dependencies
        ownDeps = ownDeps.concat(extractDepsFromRaw(rawDependency.dependency));
      });
    }
  });

  return {
    children: ownDeps,
    name: depname,
  };
}

export async function parseNuspec(dep, targetFramework) {
  const nuspecContent = await loadNuspecFromAsync(dep);
  if (nuspecContent === null) {
    return null;
  }

  return await actuallyParsedNuspec(nuspecContent, targetFramework, dep.name);
}

function extractDepsForPlainGroups(rawDependency) {
  if (!rawDependency.group) {
    return [];
  }

  return rawDependency.group.filter(group => {
    // valid group with no attributes or no `targetFramework` attribute
    return group && !(group.$ && group.$.targetFramework);
  });
}

function extractDepsForTargetFramework(rawDependency, targetFramework) {
  if (!rawDependency || !rawDependency.group) {
    return;
  }

  return rawDependency.group
    .filter(group => {
      return (
        group?.$?.targetFramework &&
        targetFrameworkRegex.test(group.$.targetFramework)
      );
    })
    .map(group => {
      const parts = group.$.targetFramework.split(targetFrameworkRegex);
      return {
        framework: parts[1],
        group,
        version: parts[2],
      };
    })
    .sort((a, b) => {
      if (a.framework === b.framework) {
        return Number(b.version) - Number(a.version);
      }

      return a.framework > b.framework ? -1 : 1;
    })
    .find(group => {
      return (
        targetFramework.framework === group.framework &&
        targetFramework.version >= group.version
      );
    });
}

function extractDepsFromRaw(rawDependencies) {
  if (!rawDependencies) {
    return [];
  }

  const deps: dependency.Dependency[] = [];
  rawDependencies.forEach(dep => {
    if (dep && dep.$) {
      deps.push({
        dependencies: {},
        name: dep.$.id,
        version: dep.$.version,
      });
    }
  });

  return deps;
}
