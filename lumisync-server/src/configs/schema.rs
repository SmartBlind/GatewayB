use crate::models::group::GroupTable;
use crate::models::region::RegionTable;
use crate::models::region_sensor::RegionSensorTable;
use crate::models::region_setting::RegionSettingTable;
use crate::models::sensor::SensorTable;
use crate::models::sensor_data::SensorDataTable;
use crate::models::setting::SettingTable;
use crate::models::Table;
use crate::models::user::UserTable;
use crate::models::user_region::UserRegionTable;
use crate::models::window::WindowTable;
use crate::models::window_setting::WindowSettingTable;

pub struct SchemaManager {
    tables: Vec<Box<dyn Table>>,
}

impl SchemaManager {
    pub fn new(tables: Vec<Box<dyn Table>>) -> Self {
        let mut manager = Self { tables };
        manager.sort_tables();
        manager
    }

    fn sort_tables(&mut self) {
        let mut sorted = vec![];
        let mut to_sort: Vec<_> = self.tables.iter().map(|t| (t.dependencies(), t.clone_table())).collect();
        let mut independent;

        while !to_sort.is_empty() {
            independent = to_sort.iter().enumerate()
                .filter(|(_, (deps, _))| deps.is_empty())
                .map(|(index, _)| index)
                .collect::<Vec<_>>();

            assert!(!independent.is_empty(), "Circular dependency detected or unresolved dependencies exist.");

            for &index in independent.iter().rev() {
                let (_, table) = to_sort.swap_remove(index);
                sorted.push(table);
            }

            to_sort.iter_mut().for_each(|(deps, _)| {
                *deps = deps.iter().filter(|dep| !sorted.iter().any(|t| t.name() == **dep)).map(|&s| s).collect();
            });
        }

        self.tables = sorted.iter().map(|t| t.clone_table()).collect();
    }

    pub fn create_schema(&self) -> Vec<String> {
        self.tables.iter().map(|table| table.create()).collect()
    }

    pub fn dispose_schema(&self) -> Vec<String> {
        self.tables.iter().rev().map(|table| table.dispose()).collect()
    }
}

impl Default for SchemaManager {
    fn default() -> Self {
        SchemaManager::new(
            vec![
                Box::new(GroupTable),
                Box::new(UserTable),
                Box::new(RegionTable),
                Box::new(SettingTable),
                Box::new(WindowTable),
                Box::new(SensorTable),
                Box::new(SensorDataTable),
                Box::new(WindowSettingTable),
                Box::new(RegionSettingTable),
                // Reference
                Box::new(UserRegionTable),
                Box::new(RegionSensorTable),
            ]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockGroupTable;
    impl Table for MockGroupTable {
        fn name(&self) -> &'static str {
            "groups"
        }

        fn create(&self) -> String {
            "CREATE TABLE groups;".to_string()
        }
        fn dispose(&self) -> String {
            "DROP TABLE groups;".to_string()
        }
        fn dependencies(&self) -> Vec<&'static str> {
            vec![]
        }
    }

    #[derive(Clone)]
    struct MockUserTable;
    impl Table for MockUserTable {
        fn name(&self) -> &'static str {
            "users"
        }

        fn create(&self) -> String {
            "CREATE TABLE users;".to_string()
        }
        fn dispose(&self) -> String {
            "DROP TABLE users;".to_string()
        }
        fn dependencies(&self) -> Vec<&'static str> {
            vec!["groups"]
        }
    }

    #[derive(Clone)]
    struct MockRegionTable;
    impl Table for MockRegionTable {
        fn name(&self) -> &'static str {
            "regions"
        }

        fn create(&self) -> String {
            "CREATE TABLE regions;".to_string()
        }

        fn dispose(&self) -> String {
            "DROP TABLE regions;".to_string()
        }

        fn dependencies(&self) -> Vec<&'static str> {
            vec!["groups"]
        }
    }

    #[derive(Clone)]
    struct MockUserRegionTable;
    impl Table for MockUserRegionTable {
        fn name(&self) -> &'static str {
            "users_regions_link"
        }

        fn create(&self) -> String {
            "CREATE TABLE users_regions_link;".to_string()
        }

        fn dispose(&self) -> String {
            "DROP TABLE users_regions_link;".to_string()
        }

        fn dependencies(&self) -> Vec<&'static str> {
            vec!["users", "regions"]
        }
    }

    #[test]
    fn test_correct_creation_order() {
        let tables: Vec<Box<dyn Table>> = vec![
            Box::new(MockUserRegionTable {}),
            Box::new(MockRegionTable {}),
            Box::new(MockUserTable {}),
            Box::new(MockGroupTable {}),
        ];

        let manager = SchemaManager::new(tables);
        let statements = manager.create_schema();

        assert_eq!(statements[0], "CREATE TABLE groups;");
        assert_eq!(statements[1], "CREATE TABLE users;");
        assert_eq!(statements[2], "CREATE TABLE regions;");
        assert_eq!(statements[3], "CREATE TABLE users_regions_link;");
    }
}
