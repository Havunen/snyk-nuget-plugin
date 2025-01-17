import * as JSZip from 'jszip';
import * as fs from 'fs';
import * as path from 'path';
import * as parseXML from 'xml2js';
import * as dependency from './dependency';
import * as debugModule from 'debug';
const debug = debugModule('snyk');

const targetFrameworkRegex = /([.a-zA-Z]+)([.0-9]+)/;

export async function parseNuspec(dep, targetFramework) {
  return Promise.resolve()
    .then(() => {
      const nupkgPath = path.resolve(
        dep.path,
        dep.name + '.' + dep.version + '.nupkg',
      );
      const nupkgData = fs.readFileSync(nupkgPath);
      return JSZip.loadAsync(nupkgData);
    })
    .then(nuspecZipData => {
      const nuspecFiles = Object.keys(nuspecZipData.files).filter(file => {
        return path.extname(file) === '.nuspec';
      });
      return nuspecZipData.files[nuspecFiles[0]].async('text');
    })
    .then(nuspecContent => {
      return new Promise((resolve, reject) => {
        parseXML.parseString(nuspecContent, (err, result) => {
          if (err) {
            return reject(err);
          }

          let ownDeps: any = [];
          // We are only going to check the first targetFramework we encounter
          // in the future we may want to support multiple, but only once
          // we have dependency version conflict resolution implemented
          result.package.metadata.forEach(metadata => {
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
              const depsFromPlainGroups = extractDepsForPlainGroups(
                rawDependency,
              );

              if (depsFromPlainGroups) {
                depsFromPlainGroups.forEach(depGroup => {
                  ownDeps = ownDeps.concat(
                    extractDepsFromRaw(depGroup.dependency),
                  );
                });
              }

              // Add the default dependencies
              ownDeps = ownDeps.concat(
                extractDepsFromRaw(rawDependency.dependency),
              );
            });
          });

          return resolve({
            children: ownDeps,
            name: dep.name,
          });
        });
      });
    })
    .catch(err => {
      // parsing problems are coerced into an empty nuspec
      debug('Error parsing dependency', JSON.stringify(dep), err);
      return null;
    });
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
