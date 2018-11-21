The `.mvn` directory was introduced in the Maven 3.3 series and has several intended uses.

However, one of its undocumented uses is that, if present, the Maven property `maven.multiModuleProjectDirectory` will always point to the project's root directory, which is useful. It's probably a bug that the behavior changes when `.mvn` is not present.
