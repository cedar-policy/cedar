#![allow(clippy::use_self)]

use super::models;
use cedar_policy_core::{ast, entities, extensions};
use std::sync::Arc;

impl From<&models::Entities> for entities::Entities {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Entities) -> Self {
        let entities: Vec<Arc<ast::Entity>> = v
            .entities
            .iter()
            .map(|e| Arc::new(ast::Entity::from(e)))
            .collect();

        #[cfg(not(feature = "partial-eval"))]
        let result = entities::Entities::new();

        #[cfg(feature = "partial-eval")]
        let mut result = entities::Entities::new();
        #[cfg(feature = "partial-eval")]
        if v.mode == models::Mode::Partial as i32 {
            result = result.partial();
        }

        result
            .add_entities(
                entities,
                None::<&entities::NoEntitiesSchema>,
                entities::TCComputation::AssumeAlreadyComputed,
                extensions::Extensions::none(),
            )
            .expect("Should be able to add entities")
    }
}

impl From<&entities::Entities> for models::Entities {
    fn from(v: &entities::Entities) -> Self {
        let entities: Vec<models::Entity> = v.iter().map(models::Entity::from).collect();

        if cfg!(feature = "partial-eval") && v.is_partial() {
            Self {
                entities,
                mode: models::Mode::Partial.into(),
            }
        } else {
            Self {
                entities,
                mode: models::Mode::Concrete.into(),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use smol_str::SmolStr;
    use std::collections::{BTreeMap, HashMap, HashSet};

    #[test]
    fn entities_roundtrip() {
        // Empty Test
        let entities1 = entities::Entities::new();
        assert_eq!(
            entities1,
            entities::Entities::from(&models::Entities::from(&entities1))
        );

        // Single Element Test
        let attrs = (1..=7)
            .map(|id| (format!("{id}").into(), ast::RestrictedExpr::val(true)))
            .collect::<HashMap<SmolStr, _>>();
        let entity = Arc::new(
            ast::Entity::new(
                r#"Foo::"bar""#.parse().unwrap(),
                attrs.clone(),
                HashSet::new(),
                BTreeMap::new(),
                extensions::Extensions::none(),
            )
            .unwrap(),
        );
        let mut entities2 = entities::Entities::new();
        entities2 = entities2
            .add_entities(
                std::iter::once(entity.clone()),
                None::<&entities::NoEntitiesSchema>,
                entities::TCComputation::AssumeAlreadyComputed,
                extensions::Extensions::none(),
            )
            .unwrap();
        assert_eq!(
            entities2,
            entities::Entities::from(&models::Entities::from(&entities2))
        );

        // Two Element Test
        let entity2 = Arc::new(
            ast::Entity::new(
                r#"Bar::"foo""#.parse().unwrap(),
                attrs,
                HashSet::new(),
                BTreeMap::new(),
                extensions::Extensions::none(),
            )
            .unwrap(),
        );
        let mut entities3 = entities::Entities::new();
        entities3 = entities3
            .add_entities(
                [entity, entity2],
                None::<&entities::NoEntitiesSchema>,
                entities::TCComputation::AssumeAlreadyComputed,
                extensions::Extensions::none(),
            )
            .unwrap();
        assert_eq!(
            entities3,
            entities::Entities::from(&models::Entities::from(&entities3))
        );
    }
}
